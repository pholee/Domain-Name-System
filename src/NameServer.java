import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


// DO NOT EDIT starts
interface NameServerInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;
    public void handleIncomingQueries(int port) throws Exception;
}
// DO NOT EDIT ends


public class NameServer implements NameServerInterface {

    // Delegates to iterative function
    private IterativeResolutionFunction engine;

    // Shared socket used for receiving/sending
    private DatagramSocket serverSocket;
    // Guards serverSocket.send()
    private final Object sendLock = new Object();
    // Guards against blocks
    private final ExecutorService pool = Executors.newCachedThreadPool();


    // CACHE

    // TTL when upstream response carries no SOA minimum
    private static final long NEGATIVE_TTL_SECONDS = 300;
    // Upper bound on how long a negative entry is trusted
    private static final long MAX_NEGATIVE_TTL_SECONDS = 3600;
    // Lower bound on how long any positive record is cached
    private static final long MIN_POSITIVE_TTL_SECONDS = 1;

    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<String, CacheEntry>();

    private static class CacheEntry {
        // Cached records
        List<DnsWire.ResourceRecord> resourceRecords;
        // Expiry time
        long expiresAt;
        // Negative entry?
        boolean negative;
    }

    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
        // This method must be called first.
        // You can assume that the IP address and port number lead to
        // a working domain name server which supports iterative
        // queries.

        if (ipAddress == null) {
            throw new Exception("setNameServer: ipAddress must not be null");
        }
        this.engine = new IterativeResolutionFunction(ipAddress, port);
    }

    public void handleIncomingQueries(int port) throws Exception {
        // You can assume that port is a valid UDP port number.
        //
        // Listens for incoming DNS queries on the given port number
        // and responds to them by using cached values and performing
        // iterative resolution.

        // Error
        if (engine == null) {
            throw new Exception("Name server not set - call setNameServer first");
        }
        serverSocket = new DatagramSocket(port);

        // Sweeps expired cache entries in the background
        Thread sweeper = new Thread(new Runnable() {
            public void run() {
                while (true) {
                    // Sweep every 30s
                    try {
                        Thread.sleep(30000);
                    } catch (InterruptedException ie) {
                        return;
                    }
                    long now = System.currentTimeMillis();
                    // Remove only entries that are still the same expired instance
                    for (Map.Entry<String, CacheEntry> e : cache.entrySet()) {
                        if (e.getValue().expiresAt <= now) {
                            cache.remove(e.getKey(), e.getValue());
                        }
                    }
                }
            }
        });
        // Sweeper should never keep the JVM alive on its own
        sweeper.setDaemon(true);
        sweeper.start();

        // Accept queries from multiple simultaneous clients
        while (true) {
            byte[] buf = new byte[4096];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            serverSocket.receive(packet);
            final byte[] data = java.util.Arrays.copyOf(packet.getData(), packet.getLength());
            final InetAddress clientAddr = packet.getAddress();
            final int clientPort = packet.getPort();
            pool.submit(new Runnable() {
                public void run() {
                    handleQuery(data, clientAddr, clientPort);
                }
            });
        }
    }

    // HELPERS

    // Parses, validates and answers a single query
    private void handleQuery(byte[] data, InetAddress clientAddr, int clientPort) {
        DnsWire.Message query;
        try {
            query = DnsWire.parseMessage(data, data.length);
        } catch (Exception malformed) {
            // Defend against malformed/malicious packets
            return;
        }
        try {
            // Ignore anything that is not a query
            if (query.qr) {
                return;
            }
            // No question
            if (query.questions.isEmpty()) {
                return;
            }
            DnsWire.Question q = query.questions.get(0);
            // Only IC queries are supported
            if (q.dnsClass != DnsWire.CLASS_IN) {
                sendError(query.id, q, query.rd, 4, clientAddr, clientPort);
                return;
            }
            int type = q.type;
            // Only the record types this server knows how to resolve/encode
            if (type != DnsWire.TYPE_A && type != DnsWire.TYPE_NS && type != DnsWire.TYPE_CNAME
                    && type != DnsWire.TYPE_MX && type != DnsWire.TYPE_TXT) {
                sendError(query.id, q, query.rd, 4, clientAddr, clientPort);
                return;
            }

            CacheEntry entry;
            try {
                // Cache-first lookup, falling back to iterative resolution on a miss
                entry = resolveWithCache(q.name, type);
            } catch (Exception resolutionFailure) {
                sendError(query.id, q, query.rd, 2, clientAddr, clientPort);
                return;
            }

            // Build and send the successful reply
            byte[] resp = buildResponse(query.id, q, query.rd, entry);
            DatagramPacket respPacket = new DatagramPacket(resp, resp.length, clientAddr, clientPort);
            synchronized (sendLock) {
                serverSocket.send(respPacket);
            }
        } catch (Exception e) {
            // Guard against bad query
        }
    }

    // Send empty-answer response carrying the given eRCODE
    private void sendError(int id, DnsWire.Question q, boolean rd, int rcode, InetAddress clientAddr, int clientPort) {
        try {
            CacheEntry empty = new CacheEntry();
            empty.negative = true;
            empty.resourceRecords = new ArrayList<DnsWire.ResourceRecord>();
            empty.expiresAt = System.currentTimeMillis();
            byte[] resp = buildResponseWithRCode(id, q, rd, empty, rcode);
            DatagramPacket respPacket = new DatagramPacket(resp, resp.length, clientAddr, clientPort);
            synchronized (sendLock) {
                serverSocket.send(respPacket);
            }
        } catch (Exception ignored) {
            // Best effort only
        }
    }

    // Returns cache entry for name/type
    private CacheEntry resolveWithCache(String name, int type) throws Exception {
        String key = DnsWire.normalizeName(name) + "|" + type;
        long now = System.currentTimeMillis();

        CacheEntry cached = cache.get(key);
        if (cached != null) {
            // Within TTL
            if (cached.expiresAt > now) {
                return cached;
            }
            // Expired
            cache.remove(key, cached);
        }

        // Perform a fresh iterative resolution if unvailable in cache
        DnsWire.Message resp = engine.resolve(name, type);
        CacheEntry entry = new CacheEntry();

        if (resp.rcode == 3 || resp.answers.isEmpty()) {
            // Cache as a negative result
            entry.negative = true;
            entry.resourceRecords = new ArrayList<DnsWire.ResourceRecord>();
            entry.expiresAt = now + negativeTtlSeconds(resp) * 1000L;
        } else {
            // Collect matching answers and track the smallest TTL among them (cached sets must expire together)
            List<DnsWire.ResourceRecord> matching = new ArrayList<DnsWire.ResourceRecord>();
            long minTtl = -1;
            for (DnsWire.ResourceRecord resourceRecord : resp.answers) {
                matching.add(resourceRecord);
                long t = resourceRecord.ttl < 0 ? 0 : resourceRecord.ttl;
                if (minTtl < 0 || t < minTtl) {
                    minTtl = t;
                }
            }
            if (matching.isEmpty()) {
                // Defensive fallback
                entry.negative = true;
                entry.resourceRecords = new ArrayList<DnsWire.ResourceRecord>();
                entry.expiresAt = now + negativeTtlSeconds(resp) * 1000L;
            } else {
                entry.negative = false;
                entry.resourceRecords = matching;
                // Never cache a positive entry for less than the configured floor
                if (minTtl < MIN_POSITIVE_TTL_SECONDS) {
                    minTtl = MIN_POSITIVE_TTL_SECONDS;
                }
                entry.expiresAt = now + minTtl * 1000L;
            }
        }

        // Store in cache and return
        cache.put(key, entry);
        return entry;
    }

    // Picks tTTL to use
    private long negativeTtlSeconds(DnsWire.Message resp) {
        for (DnsWire.ResourceRecord resourceRecord : resp.authorities) {
            if (resourceRecord.type == DnsWire.TYPE_SOA && resourceRecord.soaMinimumTtl >= 0) {
                long ttl = Math.min(resourceRecord.soaMinimumTtl, MAX_NEGATIVE_TTL_SECONDS);
                return Math.max(ttl, MIN_POSITIVE_TTL_SECONDS);
            }
        }
        // No SOA minimum available, use default
        return NEGATIVE_TTL_SECONDS;
    }

    // Builds a response
    private byte[] buildResponse(int id, DnsWire.Question q, boolean rd, CacheEntry entry) throws Exception {
        // Negative entries reported to client
        int rcode = entry.negative ? 3 : 0;
        return buildResponseWithRCode(id, q, rd, entry, rcode);
    }

    // Assembles response
    private byte[] buildResponseWithRCode
    (int id, DnsWire.Question q, boolean rd, CacheEntry entry, int rcode) throws Exception {
        long now = System.currentTimeMillis();
        // Negative entries carry no answer records
        List<DnsWire.ResourceRecord> resourceRecords = entry.negative ? new ArrayList<DnsWire.ResourceRecord>() : entry.resourceRecords;
        int ancount = resourceRecords.size();

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        // Echo back message ID sent by client
        out.write((id >> 8) & 0xFF);
        out.write(id & 0xFF);
        // Question/Response
        int flags = 0x8000;
        // Echo flag as client requested
        if (rd) {
            flags |= 0x0100;
        }
        // Recursion Available
        flags |= 0x0080;
        flags |= (rcode & 0xF);
        out.write((flags >> 8) & 0xFF);
        out.write(flags & 0xFF);
        out.write(0);
        // QDCOUNT
        out.write(1);
        out.write((ancount >> 8) & 0xFF);
        out.write(ancount & 0xFF);
        out.write(0);
        // NSCOUNT
        out.write(0);
        out.write(0);
        // ARCOUNT
        out.write(0);
        // Echo back the question
        out.write(DnsWire.encodeName(q.name));
        out.write((q.type >> 8) & 0xFF);
        out.write(q.type & 0xFF);
        out.write((DnsWire.CLASS_IN >> 8) & 0xFF);
        out.write(DnsWire.CLASS_IN & 0xFF);

        // One answer record per cached resource record
        for (DnsWire.ResourceRecord resourceRecord : resourceRecords) {
            long ttl = Math.max(0, (entry.expiresAt - now) / 1000);
            out.write(DnsWire.encodeName(resourceRecord.name));
            out.write((resourceRecord.type >> 8) & 0xFF);
            out.write(resourceRecord.type & 0xFF);
            out.write((DnsWire.CLASS_IN >> 8) & 0xFF);
            out.write(DnsWire.CLASS_IN & 0xFF);
            out.write((int) ((ttl >> 24) & 0xFF));
            out.write((int) ((ttl >> 16) & 0xFF));
            out.write((int) ((ttl >> 8) & 0xFF));
            out.write((int) (ttl & 0xFF));
            byte[] rdata = encodeRData(resourceRecord);
            out.write((rdata.length >> 8) & 0xFF);
            out.write(rdata.length & 0xFF);
            out.write(rdata);
        }
        return out.toByteArray();
    }

    // Encodes RDATA portion of a resource record
    private byte[] encodeRData(DnsWire.ResourceRecord resourceRecord) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

        switch (resourceRecord.type) {

            case DnsWire.TYPE_A: {
                String[] parts = resourceRecord.ipAddress.split("\\.");
                for (String p : parts) {
                    out.write(Integer.parseInt(p) & 0xFF);
                }
                break;
            }
            case DnsWire.TYPE_NS:
            case DnsWire.TYPE_CNAME:
                out.write(DnsWire.encodeName(resourceRecord.domainName));
                break;
            // 16-bit preference followed by encoded exchange domain name
            case DnsWire.TYPE_MX:
                out.write((resourceRecord.preference >> 8) & 0xFF);
                out.write(resourceRecord.preference & 0xFF);
                out.write(DnsWire.encodeName(resourceRecord.domainName));
                break;
            case DnsWire.TYPE_TXT: {
                String text = resourceRecord.txtData == null ? "" : resourceRecord.txtData;
                byte[] bytes = text.getBytes("US-ASCII");
                int offset = 0;
                // Empty txt
                if (bytes.length == 0) {
                    out.write(0);
                }
                // Calculate offset
                while (offset < bytes.length) {
                    int chunk = Math.min(255, bytes.length - offset);
                    out.write(chunk);
                    out.write(bytes, offset, chunk);
                    offset += chunk;
                }
                break;
            }
            default:
                break;
        }
        return out.toByteArray();
    }
}

