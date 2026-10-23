// DO NOT EDIT starts
import java.net.InetAddress;

public class TestResolver {

    public static void main(String[] args) {
        try {
            Resolver r = new Resolver();

            // Use a.root-servers.net.
            // It's IP is 198.41.0.4
            // But Java has bytes as signed so we have to represent
            // 0xC6 as -58 rather than 198
            byte[] rootServer = new byte[]{-58,41,0,4};
            r.setNameServer(InetAddress.getByAddress(rootServer), 53);

            // Try to look up some records
            InetAddress i = r.iterativeResolveAddress("moodle4-vip.city.ac.uk.");
            if (i == null) {
                System.out.println("moodle4-vip.city.ac.uk. does have an A record.  That should work?");
                return;
            } else {
                System.out.println("moodle4-vip.city.ac.uk.\tA\t" + i.toString() );
            }

            String txt = r.iterativeResolveText("city.ac.uk.");
            if (txt == null) {
                System.out.println("city.ac.uk. does have TXT records.  That should work?");
                return;

            } else {
                System.out.println("city.ac.uk.\tTXT\t" + txt );
            }


            String cn = r.iterativeResolveName("moodle4.city.ac.uk.", 5);
            if (cn == null) {
                System.out.println("moodle4.city.ac.uk. should be a CNAME.  That should work?");
                return;
            } else {
                System.out.println("moodle4.city.ac.uk.\tCNAME\t" + cn);
            }


        } catch (Exception e) {
            System.out.println("Exception caught");
            e.printStackTrace();
            return;
        }

        System.out.println("Starting tests complete!");
        System.out.println("You are on your way!");
        System.out.println("You will need to write your own tests to make sure that everything works.");
        return;
    }
}
// DO NOT EDIT ends
