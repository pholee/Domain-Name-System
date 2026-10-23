import java.net.InetAddress;

// DO NOT EDIT starts
interface ResolverInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;

    public InetAddress iterativeResolveAddress(String domainName) throws Exception;
    public String iterativeResolveText(String domainName) throws Exception;
    public String iterativeResolveName(String domainName, int type) throws Exception;
}
// DO NOT EDIT ends


public class Resolver implements ResolverInterface {

    // Delegates to iterative function
    private IterativeResolutionFunction engine;

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

    public InetAddress iterativeResolveAddress(String domainName) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // Performs a iterative resolution for domainName's A resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has A records, it returns the IP
        // address from one of them.  If there is no record then it
        // returns null.  In any other case it throws an informative
        // exception.

        DnsWire.Message response = resolve(domainName, DnsWire.TYPE_A);

        // Error: domain does not exist
        if (response.rcode == 3) {
            return null;
        }

        // Scan answers for the first A record and return its address
        for (DnsWire.ResourceRecord resourceRecord : response.answers) {
            if (resourceRecord.type == DnsWire.TYPE_A && resourceRecord.ipAddress != null) {
                return InetAddress.getByName(resourceRecord.ipAddress);
            }
        }

        // No A record exists
        return null;
    }

    public String iterativeResolveText(String domainName) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // Performs a iterative resolution for domainName's TXT resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has TXT records, it returns the string
        // contained one of the records. If there is no record then it
        // returns null.  In any other case it throws an informative
        // exception.

        DnsWire.Message response = resolve(domainName, DnsWire.TYPE_TXT);

        // Error: domain does not exist
        if (response.rcode == 3) {
            return null;
        }

        // Scan answers for the first TXT record and return its text
        for (DnsWire.ResourceRecord resourceRecord : response.answers) {
            if (resourceRecord.type == DnsWire.TYPE_TXT && resourceRecord.txtData != null) {
                return resourceRecord.txtData;
            }
        }

        // No TXT record exists
        return null;
    }

    public String iterativeResolveName(String domainName, int type) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // You can assume that type is one of NS, MX or CNAME.
        //
        // Performs a iterative resolution for domainName's resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has appropriate records, it returns the
        // domain name contained in one of the records. If there is no
        // record then it returns null.  In any other case it throws
        // an informative exception.

        // Error: reject any resource type that is not TYPE_NS
        if (type != DnsWire.TYPE_NS && type != DnsWire.TYPE_MX && type != DnsWire.TYPE_CNAME) {
            throw new Exception("iterativeResolveName: unsupported type " + type + " (expected NS=2, CNAME=5 or MX=15)");
        }

        DnsWire.Message response = resolve(domainName, type);

        // Error: domain does not exist
        if (response.rcode == 3) {
            return null;
        }

        // Scan answers for the first matching record and return its domain name
        for (DnsWire.ResourceRecord resourceRecord : response.answers) {
            if (resourceRecord.type == type && resourceRecord.domainName != null) {
                return resourceRecord.domainName;
            }
        }

        // No matching record exists
        return null;
    }

    // HELPERS

    // Delegates iterative resolution to function
    private DnsWire.Message resolve(String name, int qtype) throws Exception {
        // Error: setNameServer never called
        if (engine == null) {
            throw new Exception("Name server not set - call setNameServer first");
        }
        return engine.resolve(name, qtype);
    }
}
