import spf_resolver.SpfReult;

public class SpfUtils {

        private SpfUtils(){}

    private static int ipToInt(String ip){
        int result = 0;
        int shiftBy=24;
        String[] ipElements = ip.split("\\.");
        for(String s : ipElements){
            result += Integer.parseInt(s)<<shiftBy;
            shiftBy-=8;
        }
        return result;
    }

    private static int prefixToMask(int prefix){
        if(prefix == 0) return 0;
        int result = -1; // -1 = 1111111111111111
        return result<< 32-prefix;

    }

    public static boolean matchesCidr(String ip, String cidr){
        int hostIp = ipToInt(ip);
        String[] parts = cidr.split("/");
        int spfIp = ipToInt(parts[0]);
        int mask = prefixToMask(Integer.parseInt(parts[1]));
        return (hostIp&mask)==(spfIp&mask);
    }

}
