import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

// DO NOT EDIT starts
interface StubResolverInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;

    public InetAddress recursiveResolveAddress(String domainName) throws Exception;
    public String recursiveResolveText(String domainName) throws Exception;
    public String recursiveResolveName(String domainName, int type) throws Exception;
}
// DO NOT EDIT ends


public class StubResolver implements StubResolverInterface {

    // IP address of the configured recursive name server
    private InetAddress serverIp = null;
    // UDP port of the configured recursive name server
    private int serverPort = -1;

    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
        // This method must be called first.
        // You can assume that the IP address and port number lead to
        // a working domain name server which supports recursive
        // queries.

        if (ipAddress == null) {
            throw new Exception("setNameServer: ipAddress must not be null");
        }
        this.serverIp = ipAddress;
        this.serverPort = port;
    }

    public InetAddress recursiveResolveAddress(String domainName) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // Performs a recursive resolution for domainName's A resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has A records, it returns the IP
        // address from one of them.  If there is no record then it
        // returns null.  In any other case it throws an informative
        // exception.

        // Query the configured server for the A record
        DnsWire.Message response = query(domainName, DnsWire.TYPE_A);

        // Throws error on rcode other than NXDOMAIN
        checkRcode(response, domainName);

        // Scan answers for the first A record and return its address
        for (DnsWire.ResourceRecord resourceRecord : response.answers) {
            if (resourceRecord.type == DnsWire.TYPE_A && resourceRecord.ipAddress != null) {
                return InetAddress.getByName(resourceRecord.ipAddress);
            }
        }

        // No A record present
        return null;
    }

    public String recursiveResolveText(String domainName) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // Performs a recursive resolution for domainName's TXT resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has TXT records, it returns the string
        // contained one of the records. If there is no record then it
        // returns null.  In any other case it throws an informative
        // exception.

        // Query the configured server for the TXT record
        DnsWire.Message response = query(domainName, DnsWire.TYPE_TXT);

        // Throws error on rcode other than NXDOMAIN
        checkRcode(response, domainName);

        // Scan answers for the first TXT record and return its text
        for (DnsWire.ResourceRecord resourceRecord : response.answers) {
            if (resourceRecord.type == DnsWire.TYPE_TXT && resourceRecord.txtData != null) {
                return resourceRecord.txtData;
            }
        }

        // No TXT record present
        return null;
    }

    public String recursiveResolveName(String domainName, int type) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // You can assume that type is one of NS, MX or CNAME.
        //
        // Performs a recursive resolution for domainName's resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has appropriate records, it returns the
        // domain name contained in one of the records. If there is no
        // record then it returns null.  In any other case it throws
        // an informative exception.

        // Error: reject any resource type that is not TYPE_NS
        if (type != DnsWire.TYPE_NS && type != DnsWire.TYPE_MX && type != DnsWire.TYPE_CNAME) {
            throw new Exception("recursiveResolveName: unsupported type " + type + " (expected NS=2, CNAME=5 or MX=15)");
        }

        // Query the configured server for the requested record type
        DnsWire.Message response = query(domainName, type);

        // Throws error on rcode other than NXDOMAIN
        checkRcode(response, domainName);

        // Scan answers for the first matching record and return its domain name
        for (DnsWire.ResourceRecord resourceRecord : response.answers) {
            if (resourceRecord.type == type && resourceRecord.domainName != null) {
                return resourceRecord.domainName;
            }
        }

        // No matching record present
        return null;
    }

    // HELPERS

    // Generates error text for R-CODE
    private void checkRcode(DnsWire.Message response, String domainName) throws Exception {
        if (response.rcode == 3) {
            return;
        }
        if (response.rcode != 0) {
            throw new Exception("Name server " + serverIp + ":" + serverPort +
                    " returned error RCODE=" + response.rcode + " for " + domainName);
        }
    }

    // Recursive query handling
    private DnsWire.Message query(String name, int qtype) throws Exception {
        // Error: setNameServer was never called
        if (serverIp == null) {
            throw new Exception("Name server not set - call setNameServer first");
        }

        // Remember most recent timeout
        Exception lastError = null;

        // For loop: retry up to 3 times, with a growing timeout each time
        for (int attempt = 0; attempt < 3; attempt++) {
            DatagramSocket socket = null;

            try {
                // Set random query/response identifier each try
                int id = DnsWire.randomId();

                // Build the wire-format query, with EDNS enabled to signal a larger UDP payload
                byte[] queryBytes = DnsWire.buildQuery(name, qtype, id, true, true);

                socket = new DatagramSocket();

                // Timeout grows with each retry: 2s, 3.5s, 5s
                int timeoutMs = 2000 + attempt * 1500;

                // Send the query to the configured server
                DatagramPacket sendPacket = new DatagramPacket(queryBytes, queryBytes.length, serverIp, serverPort);
                socket.send(sendPacket);

                // Set max timeout
                long deadline = System.currentTimeMillis() + timeoutMs;

                while (true) {
                    // Timeout calculator
                    long remaining = deadline - System.currentTimeMillis();
                    if (remaining <= 0) {
                        throw new SocketTimeoutException("Timed out waiting for a response");
                    }

                    // Re-arm the socket timeout with whatever time remains
                    socket.setSoTimeout((int) remaining);
                    byte[] buf = new byte[4096];
                    DatagramPacket recvPacket = new DatagramPacket(buf, buf.length);
                    socket.receive(recvPacket);

                    // Defend against spoofed/unrelated packets
                    if (!recvPacket.getAddress().equals(serverIp) || recvPacket.getPort() != serverPort) {
                        continue;
                    }

                    // Parse the reply
                    DnsWire.Message msg;
                    try {
                        msg = DnsWire.parseMessage(recvPacket.getData(), recvPacket.getLength());
                    } catch (Exception malformed) {
                        continue;
                    }
                    // Query/response ID must match
                    if (msg.id != id) {
                        continue;
                    }
                    // Must be a response
                    if (!msg.qr) {
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
            } catch (SocketTimeoutException e) {
                // Record and fall through to the next retry attempt
                lastError = e;
            } finally {
                // Always release the socket before retrying or returning
                if (socket != null) {
                    socket.close();
                }
            }
        }
        // All retries exhausted without valid response
        throw new Exception("No response from name server " + serverIp + ":" + serverPort +
                " while resolving " + name, lastError);
    }
}
