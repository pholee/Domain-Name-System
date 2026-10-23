import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class IterativeResolutionFunction {

    // Caps number of delegation referrals for single query (guards against referral loop)
    private static final int MAX_REFERRALS = 30;
    // Caps number of CNAME redirections for single query
    private static final int MAX_CNAME_HOPS = 20;
    // Caps recursive depth when resolving a name servers address (glueless referral)
    private static final int MAX_GLUE_DEPTH = 4;

    // Address of server every top-level query starts from
    private final InetAddress startIp;
    // Port of server every top-level query starts from
    private final int startPort;

    IterativeResolutionFunction(InetAddress startIp, int startPort) {
        this.startIp = startIp;
        this.startPort = startPort;
    }

    // Resolves domain name and qtype starting from the configured server
    DnsWire.Message resolve(String name, int qtype) throws Exception {
        return iterativeQuery(name, qtype, 0);
    }

    // Candidate server to try next (already resolved to address or known by name)
    private static class ServerCandidate {
        // Resolved address
        InetAddress ip;
        int port;
        // Name servers domain name
        String nsName;

        ServerCandidate(InetAddress ip, int port, String nsName) {
            this.ip = ip;
            this.port = port;
            this.nsName = nsName;
        }
    }

    private DnsWire.Message iterativeQuery(String name, int qtype, int depth) throws Exception {
        // Error: resolution loop
        if (depth > MAX_GLUE_DEPTH) {
            throw new Exception("Resolution too deep (possible name server dependency loop) resolving " + name);
        }

        // Begin every query from configured starting server
        List<ServerCandidate> servers = new ArrayList<ServerCandidate>();
        servers.add(new ServerCandidate(startIp, startPort, null));

        // Names already redirected via CNAME
        Set<String> cnamesSeen = new HashSet<String>();
        // Accumulates every CNAME hop plus final answer
        List<DnsWire.ResourceRecord> chain = new ArrayList<DnsWire.ResourceRecord>();
        // The name currently being chased
        String currentName = name;

        for (int referralHops = 0; referralHops < MAX_REFERRALS; referralHops++) {
            // Try each current candidate server until one responds
            DnsWire.Response response = queryServers(servers, currentName, qtype, depth);
            if (response == null) {
                throw new Exception("All name servers were unresponsive while resolving " + currentName);
            }
            DnsWire.Message resp = response.message;

            // Delegated servers below are assumed to listen on this port
            int answeredFromPort = response.port;

            // Generate error message if necessary
            if (resp.rcode == 3) {
                resp.answers = chain;
                return resp;
            }
            if (resp.rcode != 0) {
                throw new Exception("Name server returned error RCODE=" + resp.rcode + " while resolving " + currentName);
            }

            // Direct answer of the requested type
            boolean hasDirectAnswer = false;
            for (DnsWire.ResourceRecord resourceRecord : resp.answers) {
                if (resourceRecord.type == qtype && DnsWire.normalizeName(resourceRecord.name).equals(DnsWire.normalizeName(currentName))) {
                    hasDirectAnswer = true;
                    break;
                }
            }
            if (hasDirectAnswer) {
                // Append the final answer to the chain and return
                chain.addAll(resp.answers);
                resp.answers = chain;
                return resp;
            }

            // CNAME redirection name we are chasing
            DnsWire.ResourceRecord cname = null;
            for (DnsWire.ResourceRecord resourceRecord : resp.answers) {
                if (resourceRecord.type == DnsWire.TYPE_CNAME && DnsWire.normalizeName(resourceRecord.name).equals(DnsWire.normalizeName(currentName))) {
                    cname = resourceRecord;
                    break;
                }
            }
            if (cname != null && cname.domainName != null) {
                String target = cname.domainName;

                // Error: redirectino loop
                if (cnamesSeen.contains(DnsWire.normalizeName(currentName)) || DnsWire.normalizeName(target).equals(DnsWire.normalizeName(currentName))) {
                    throw new Exception("CNAME loop detected while resolving " + name);
                }

                cnamesSeen.add(DnsWire.normalizeName(currentName));

                // Error: max hops reached
                if (cnamesSeen.size() > MAX_CNAME_HOPS) {
                    throw new Exception("Too many CNAME redirections while resolving " + name);
                }

                chain.add(cname);
                currentName = target;

                // Restart from configured starting server for the new name
                servers = new ArrayList<ServerCandidate>();
                servers.add(new ServerCandidate(startIp, startPort, null));
                continue;
            }

            // Some answer returned but not as exected (authoritative "no data" response)
            if (!resp.answers.isEmpty()) {
                chain.addAll(resp.answers);
                resp.answers = chain;
                return resp;
            }

            // Look for delegation in authority section
            List<DnsWire.ResourceRecord> nsRecords = new ArrayList<DnsWire.ResourceRecord>();
            for (DnsWire.ResourceRecord resourceRecord : resp.authorities) {
                if (resourceRecord.type == DnsWire.TYPE_NS) {
                    nsRecords.add(resourceRecord);
                }
            }
            if (nsRecords.isEmpty()) {
                // Authoritative NODATA
                resp.answers = chain;
                return resp;
            }

            // Set trusted servers
            Map<String, List<String>> glue = new HashMap<String, List<String>>();
            for (DnsWire.ResourceRecord resourceRecord : resp.additionals) {
                if (resourceRecord.type == DnsWire.TYPE_A && resourceRecord.ipAddress != null) {
                    String key = DnsWire.normalizeName(resourceRecord.name);
                    List<String> list = glue.get(key);
                    if (list == null) {
                        list = new ArrayList<String>();
                        glue.put(key, list);
                    }
                    list.add(resourceRecord.ipAddress);
                }
            }

            // Delegated servers assumed reachable on same port as server with supplied referral
            List<ServerCandidate> next = new ArrayList<ServerCandidate>();
            for (DnsWire.ResourceRecord ns : nsRecords) {
                String nsName = ns.domainName;
                if (nsName == null) {
                    continue;
                }
                // Prefer glue if this referral supplied it (avoids extra lookup)
                List<String> addrs = glue.get(DnsWire.normalizeName(nsName));
                if (addrs != null) {
                    for (String a : addrs) {
                        next.add(new ServerCandidate(InetAddress.getByName(a), answeredFromPort, nsName));
                    }
                } else {
                    // No glue
                    next.add(new ServerCandidate(null, answeredFromPort, nsName));
                }
            }
            if (next.isEmpty()) {
                throw new Exception("Referral with no usable name servers while resolving " + currentName);
            }
            // Descend to newly delegated set of servers for ext hop
            servers = next;
        }
        throw new Exception("Too many referrals while resolving " + name + " (possible delegation loop)");
    }

    // Tries each candidate server
    private DnsWire.Response queryServers(List<ServerCandidate> servers, String name, int qtype, int depth) throws Exception {
        for (ServerCandidate sc : servers) {
            InetAddress ip = sc.ip;
            if (ip == null) {
                // Don't recurse into glueless resolution beyond configured depth
                if (depth >= MAX_GLUE_DEPTH) {
                    continue;
                }
                try {
                    // Resolve name servers own address before it can be queried
                    ip = resolveNSAddress(sc.nsName, depth + 1);
                } catch (Exception e) {
                    // Couldn't resolve, try next
                    continue;
                }
                if (ip == null) {
                    continue;
                }
            }
            DnsWire.Message resp = trySendReceive(ip, sc.port, name, qtype);
            if (resp != null) {
                return new DnsWire.Response(resp, sc.port);
            }
            // Server did not respond in time, try next
        }
        return null;
    }

    // Resolves delegated name servers own A record (so it can be queried when the referral didn't supply glue)
    private InetAddress resolveNSAddress(String nsName, int depth) throws Exception {
        if (nsName == null) {
            return null;
        }
        DnsWire.Message resp = iterativeQuery(nsName, DnsWire.TYPE_A, depth);
        if (resp == null || resp.rcode != 0) {
            return null;
        }
        // Return the first A record's address
        for (DnsWire.ResourceRecord resourceRecord : resp.answers) {
            if (resourceRecord.type == DnsWire.TYPE_A && resourceRecord.ipAddress != null) {
                return InetAddress.getByName(resourceRecord.ipAddress);
            }
        }
        return null;
    }

    private DnsWire.Message trySendReceive(InetAddress ip, int port, String name, int qtype) {
        for (int attempt = 0; attempt < 2; attempt++) {
            DatagramSocket socket = null;
            try {
                // Fresh random ID per attempt
                int id = DnsWire.randomId();
                byte[] queryBytes = DnsWire.buildQuery(name, qtype, id, false, false);
                socket = new DatagramSocket();
                // Timeout grows on retry
                int timeoutMs = 1500 + attempt * 1000;
                long deadline = System.currentTimeMillis() + timeoutMs;
                DatagramPacket sendPacket = new DatagramPacket(queryBytes, queryBytes.length, ip, port);
                socket.send(sendPacket);

                while (true) {
                    // Timeout calculator
                    long remaining = deadline - System.currentTimeMillis();
                    if (remaining <= 0) {
                        break;
                    }
                    // Re-arm the socket timeout with remaining time
                    socket.setSoTimeout((int) remaining);
                    byte[] buf = new byte[4096];
                    DatagramPacket recvPacket = new DatagramPacket(buf, buf.length);
                    socket.receive(recvPacket);

                    // Check it comes from queried server
                    if (!recvPacket.getAddress().equals(ip) || recvPacket.getPort() != port) {
                        continue;
                    }
                    // Parse reply
                    DnsWire.Message msg;
                    try {
                        msg = DnsWire.parseMessage(recvPacket.getData(), recvPacket.getLength());
                    } catch (Exception malformed) {
                        continue;
                    }
                    // ID must match and it is a response
                    if (msg.id != id || !msg.qr) {
                        continue;
                    }
                    // Must echo back the same question we asked
                    if (msg.questions.isEmpty()
                            || msg.questions.get(0).type != qtype
                            || !DnsWire.normalizeName(msg.questions.get(0).name).equals(DnsWire.normalizeName(name))) {
                        continue;
                    }
                    // Validated
                    return msg;
                }
            } catch (Exception e) {
                // Ignore and retry or fall through to try next candidate server
            } finally {
                // Release socket before retrying
                if (socket != null) {
                    socket.close();
                }
            }
        }
        // No valid response, try another server
        return null;
    }
}