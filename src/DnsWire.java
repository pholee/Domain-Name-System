import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

final class DnsWire {

    // CONSTRAINTS

    // Type codes
    // IPv4 host address
    static final int TYPE_A     = 1;
    // IPv6 host address
    static final int TYPE_AAAA  = 28;
    // Authoritative name server
    static final int TYPE_NS    = 2;
    // Canonical name for an alias
    static final int TYPE_CNAME = 5;
    // Start of a zone of authority
    static final int TYPE_SOA   = 6;
    // Mail exchange
    static final int TYPE_MX    = 15;
    // Text strings
    static final int TYPE_TXT   = 16;
    // Internet
    static final int CLASS_IN   = 1;

    // Generates a 16-bit header id for messages
    private static final Random RNG = new Random();
    static int randomId() {
        return RNG.nextInt(65536);
    }

    // Canonicalizes a domain name for comparison (see CNAME)
    static String normalizeName(String name) {
        if (name == null) {
            return "";
        }
        // Strips trailing root dot
        String n = name;
        if (n.endsWith(".")) {
            n = n.substring(0, n.length() - 1);
        }
        return n.toLowerCase();
    }

    // DATA MODEL

    static class ResourceRecord {
        // Domain name the record belongs to
        String name;
        // Type code
        int type;
        // The domain class: Internet (see CLASS_IN)
        int dnsClass;
        // Time to live of this record in cache before it must be re-queried
        long ttl;
        // Byte length of the RDATA
        int rdLength;
        // Parsed RDATA (only set relevant fields for the record type)
        String ipAddress;        // A / AAAA
        String domainName;       // NS / CNAME / MX
        int preference;          // MX
        String txtData;          // TXT
        long soaMinimumTtl = -1; // SOA
    }

    static class Question {
        // Domain name being queried
        String name;
        // Type code of record being queried
        int type;
        // The domain class: Internet (see CLASS_IN)
        int dnsClass;
    }

    static class Message {
        // HEADER
        // Identifier for each question/response pair
        int id;
        // Flags: Question/Response, RespondingServerIsAuthoritativeForQueriedName, TruncatedMessage, RecursionDesired, RecursionAvailable
        boolean qr, aa, tc, rd, ra;
        // Query code & Response code
        int opcode, rcode;
        // QUESTION
        List<Question> questions = new ArrayList<Question>();
        // ANSWER
        List<ResourceRecord> answers = new ArrayList<ResourceRecord>();
        // AUTHORITY
        List<ResourceRecord> authorities = new ArrayList<ResourceRecord>();
        // ADDITIONAL
        List<ResourceRecord> additionals = new ArrayList<ResourceRecord>();
    }

    static class Response {
        // Parsed DNS message received in response to a query
        final Message message;
        // UDP port the response was received from
        final int port;

        // Bundles response with sender info
        Response(Message message, int port) {
            this.message = message;
            this.port = port;
        }
    }

    // QUESTION ENCODING

    // Fix for handling truncated responses
    private static final int EDNS_UDP_PAYLOAD_SIZE = 4096;

    // Assembles query as byte array
    static byte[] buildQuery(String name, int qtype, int id, boolean recursionDesired, boolean includeEdns) throws Exception {
        // Buffer for raw query bytes
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Writes the high byte of the message ID
        out.write((id >> 8) & 0xFF);
        // Writes the low byte of the message ID
        out.write(id & 0xFF);
        // Start the 16-bit flags field at 0
        int flags = 0;
        // Set rd  bit
        if (recursionDesired) {
            flags |= 0x0100;
        }
        // Writes the high byte of the flags field
        out.write((flags >> 8) & 0xFF);
        // Writes the low byte of the flags field
        out.write(flags & 0xFF);
        out.write(0);
        // QDCOUNT
        out.write(1);
        out.write(0);
        // ANCOUNT
        out.write(0);
        out.write(0);
        // NSCOUNT
        out.write(0);
        out.write(0);
        // Sets ARCOUNT to 1 if EDNS truncation handling required
        out.write(includeEdns ? 1 : 0);
        // Queries domain name
        out.write(encodeName(name));
        // Writes the high byte of QTYPE
        out.write((qtype >> 8) & 0xFF);
        // Writes the low byte of QTYPE
        out.write(qtype & 0xFF);
        out.write((CLASS_IN >> 8) & 0xFF);
        out.write(CLASS_IN & 0xFF);
        // If query requires EDNS truncation handling, include UDP payload size
        if (includeEdns) {
            out.write(encodeOptRecord());
        }

        // Return
        return out.toByteArray();
    }

    // Called if includeEDNS is true
    private static byte[] encodeOptRecord() throws Exception {
        // Buffer for OptRecord bytes
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Set bits
        out.write(0);
        out.write(0);
        out.write(41);
        out.write((EDNS_UDP_PAYLOAD_SIZE >> 8) & 0xFF);
        out.write(EDNS_UDP_PAYLOAD_SIZE & 0xFF);
        out.write(0);
        out.write(0);
        out.write(0);
        out.write(0);
        out.write(0);
        out.write(0);

        // Return
        return out.toByteArray();
    }

    static byte[] encodeName(String name) throws Exception {
        // Buffer for encoded name bytes
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // If root domain server, write zero-length terminator byte and return
        if (name == null || name.isEmpty() || name.equals(".")) {
            out.write(0);
            return out.toByteArray();
        }

        // Strips trailing root dot
        String trimmed = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        // Split domain name into dot separated labels
        String[] labels = trimmed.split("\\.");
        // For each label
        for (String label : labels) {
            // Convert to ASCII bytes
            byte[] lb = label.getBytes("US-ASCII");
            // Reject empty or oversized labels
            if (lb.length == 0 || lb.length > 63) {
                throw new Exception("Invalid DNS label: '" + label + "'");
            }
            // Write encoded label
            out.write(lb.length);
            out.write(lb);
        }
        // Write terminating zero-length byte
        out.write(0);

        // Return
        return out.toByteArray();
    }

    // MESSAGE DECODING

    // Stores the output from readName
    private static class NameResult {
        String name;
        int nextOffset;
    }

    // Decodes the domain name
    private static NameResult decodeName(byte[] data, int offset) throws Exception {
        // Accumulates decoded labels with dot separation
        StringBuilder sb = new StringBuilder();
        // Current position in encoded name
        int position = offset;
        // Count of compression-pointer jumps taken (guards against loops)
        int jumps = 0;
        // Have we followed a compression pointer
        boolean jumped = false;
        // Where the original domain name ends (if we followed a pointer)
        int afterFirstPointerOffset = -1;

        // Decode domain name
        while (true) {
            //Check within bounds
            if (position < 0 || position >= data.length) {
                throw new Exception("Malformed name: offset out of range");
            }

            // Set label length equal to current position byte
            int len = data[position] & 0xFF;

            // If zero-length byte (marks the end of the name)
            if (len == 0) {
                position++;
                // If no jumps, then the end of the domain name is after this terminator
                if (!jumped) {
                    afterFirstPointerOffset = position;
                }
                break;

                // Else pointer
            } else if ((len & 0xC0) == 0xC0) {
                // Error: only one byte of 2 byte pointer exists
                if (position + 1 >= data.length) {
                    throw new Exception("Malformed compression pointer");
                }
                // Combine the low 6 bits of this byte with the next byte to form the 14-bit pointer offset
                int pointer = ((len & 0x3F) << 8) | (data[position + 1] & 0xFF);
                // Then for first pointer encountered
                if (!jumped) {
                    // Remember where reading resumes for the caller (right after this 2-byte pointer)
                    afterFirstPointerOffset = position + 2;
                    jumped = true;
                }
                jumps++;
                // Error: jump limit reached
                if (jumps > 128) {
                    throw new Exception("Too many compression pointer jumps (possible loop)");
                }
                // Set position to pointer to continue decoding
                position = pointer;

                // Else label
            } else {
                position++;
                // Error: position greater than total data length
                if (position + len > data.length) {
                    throw new Exception("Malformed label length");
                }
                // Append trailing dot to last label in StringBuilder
                if (sb.length() > 0) {
                    sb.append('.');
                }
                // Append decoded domain name label to StringBuilder
                sb.append(new String(data, position, len, "US-ASCII"));
                // Increment position
                position += len;
            }
        }

        // Store decoded name
        NameResult r = new NameResult();
        // Convert to string
        r.name = sb.toString();
        // Store nextOffset
        r.nextOffset = jumped ? afterFirstPointerOffset : position;
        // Return
        return r;
    }

    // Parses a full DNS message from raw bytes
    static Message parseMessage(byte[] data, int length) throws Exception {
        // Error: too short, does not meet header length requirement
        if (length < 12) {
            throw new Exception("Message too short to be a DNS message");
        }

        // Stores parsed message
        Message msg = new Message();

        // 16 bit identifier
        msg.id = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
        // 16 bit flags field
        int flags = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        // Query or response
        msg.qr = (flags & 0x8000) != 0;
        // Operation code
        msg.opcode = (flags >> 11) & 0xF;
        // Authoritative answer
        msg.aa = (flags & 0x0400) != 0;
        // Truncated
        msg.tc = (flags & 0x0200) != 0;
        // Recursion desired
        msg.rd = (flags & 0x0100) != 0;
        // Recursion available
        msg.ra = (flags & 0x0080) != 0;
        // Response code
        msg.rcode = flags & 0xF;
        // QDCOUND, ANCOUNT, NSCOUNT, ARCOUNT
        int qdcount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
        int ancount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        int nscount = ((data[8] & 0xFF) << 8) | (data[9] & 0xFF);
        int arcount = ((data[10] & 0xFF) << 8) | (data[11] & 0xFF);

        // Error: record counts too large (defends against malformed/malicious packets)
        if (qdcount > 16 || ancount > 4096 || nscount > 4096 || arcount > 4096) {
            throw new Exception("Implausible section counts in DNS message");
        }

        // Start from after the header
        int offset = 12;

        // Decode each question entry
        for (int i = 0; i < qdcount; i++) {
            // Decode the queried domain  name
            NameResult nr = decodeName(data, offset);
            // Go to after domain name
            offset = nr.nextOffset;
            // Error: account for QTYPE and QCLASS
            if (offset + 4 > length) {
                throw new Exception("Truncated question section");
            }
            // Store decoded question
            Question q = new Question();
            q.name = nr.name;
            q.type = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;
            q.dnsClass = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;
            msg.questions.add(q);
        }

        // Decode each answers entry
        offset = parseResourceRecord(data, offset, ancount, msg.answers, length);

        // Decode each authorities entry
        offset = parseResourceRecord(data, offset, nscount, msg.authorities, length);

        // Decode each additionals entry
        offset = parseResourceRecord(data, offset, arcount, msg.additionals, length);

        // Return full message
        return msg;
    }

    // Decodes resource records starting from an offset and returns the full list and updated offset
    private static int parseResourceRecord(byte[] data, int offset, int count, List<ResourceRecord> list, int length) throws Exception {
        // For loop
        for (int i = 0; i < count; i++) {
            // Domain name
            NameResult nr = decodeName(data, offset);
            // Fixed bytes
            offset = nr.nextOffset;
            if (offset + 10 > length) {
                throw new Exception("Truncated resource record");
            }

            // Read resource record information and create new object
            ResourceRecord resourceRecord = new ResourceRecord();
            resourceRecord.name = nr.name;
            resourceRecord.type = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;
            resourceRecord.dnsClass = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;
            long ttl = ((long) (data[offset] & 0xFF) << 24)
                    | ((data[offset + 1] & 0xFF) << 16)
                    | ((data[offset + 2] & 0xFF) << 8)
                    | (data[offset + 3] & 0xFF);
            resourceRecord.ttl = ttl;
            offset += 4;
            int rdlength = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            offset += 2;

            // Error: overflow
            if (offset + rdlength > length) {
                throw new Exception("Truncated RDATA");
            }

            // Start at offset
            int rdataStart = offset;

            // Decode resource records
            switch (resourceRecord.type) {
                case TYPE_A:
                    if (rdlength == 4) {
                        resourceRecord.ipAddress = (data[rdataStart] & 0xFF) + "." + (data[rdataStart + 1] & 0xFF) + "."
                                + (data[rdataStart + 2] & 0xFF) + "." + (data[rdataStart + 3] & 0xFF);
                    }
                    break;
                case TYPE_AAAA:
                    if (rdlength == 16) {
                        StringBuilder sb = new StringBuilder();
                        for (int b = 0; b < 16; b += 2) {
                            if (b > 0) {
                                sb.append(':');
                            }
                            int v = ((data[rdataStart + b] & 0xFF) << 8) | (data[rdataStart + b + 1] & 0xFF);
                            sb.append(Integer.toHexString(v));
                        }
                        resourceRecord.ipAddress = sb.toString();
                    }
                    break;
                case TYPE_NS:
                case TYPE_CNAME: {
                    NameResult t = decodeName(data, rdataStart);
                    resourceRecord.domainName = t.name;
                    break;
                }
                case TYPE_MX: {
                    if (rdlength >= 2) {
                        int pref = ((data[rdataStart] & 0xFF) << 8) | (data[rdataStart + 1] & 0xFF);
                        resourceRecord.preference = pref;
                        NameResult t = decodeName(data, rdataStart + 2);
                        resourceRecord.domainName = t.name;
                    }
                    break;
                }
                case TYPE_TXT: {
                    StringBuilder sb = new StringBuilder();
                    int p = rdataStart;
                    int end = rdataStart + rdlength;
                    while (p < end) {
                        int slen = data[p] & 0xFF;
                        p++;
                        if (p + slen > end) {
                            break;
                        }
                        sb.append(new String(data, p, slen, "US-ASCII"));
                        p += slen;
                    }
                    resourceRecord.txtData = sb.toString();
                    break;
                }
                case TYPE_SOA: {
                    try {
                        NameResult mname = decodeName(data, rdataStart);
                        NameResult rname = decodeName(data, mname.nextOffset);
                        int p = rname.nextOffset;
                        if (p + 20 <= rdataStart + rdlength) {
                            // serial(4) refresh(4) retry(4) expire(4) minimum(4)
                            long minimum = ((long) (data[p + 16] & 0xFF) << 24)
                                    | ((data[p + 17] & 0xFF) << 16)
                                    | ((data[p + 18] & 0xFF) << 8)
                                    | (data[p + 19] & 0xFF);
                            resourceRecord.soaMinimumTtl = minimum;
                        }
                    } catch (Exception ignore) {
                        // best-effort only
                    }
                    break;
                }
                default:
                    break;
            }
            // Return
            resourceRecord.rdLength = rdlength;
            list.add(resourceRecord);
            offset = rdataStart + rdlength;
        }
        return offset;
    }
}
