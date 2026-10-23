// DO NOT EDIT starts
import java.net.InetAddress;

public class TestNameServer {

    public static void main(String[] args) {
        try {
            NameServer ns = new NameServer();

            // Use a.root-servers.net.
            // It's IP is 198.41.0.4
            // But Java has bytes as signed so we have to represent
            // 0xC6 as -58 rather than 198
            byte[] rootServer = new byte[]{-58,41,0,4};
            ns.setNameServer(InetAddress.getByAddress(rootServer), 53);

            // Note that this is a non-standard port number
            // so clients will need to be configured to use it.
            // Changing this to 53 would also work but may require
            // running the code with elevated priviledges.
            ns.handleIncomingQueries(7364);

        } catch (Exception e) {
            System.out.println("Exception caught");
            e.printStackTrace();
        }

        return;
    }
}
// DO NOT EDIT ends

