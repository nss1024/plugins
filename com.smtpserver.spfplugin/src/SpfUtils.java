import spf_resolver.SpfReult;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

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

    public static boolean matchesIpv6Cidr(String hostIp, String spfIpRange){
        InetAddress hostAddress, spfAddress = null;
        String[] parts = spfIpRange.split("/");
        String spfPrefix = parts[1];
        try {
            hostAddress = InetAddress.getByName(hostIp);
            spfAddress = InetAddress.getByName(parts[0]);

        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        BigInteger hostIpNo = ip6ToBigint(hostAddress);
        BigInteger spfAddressNo = ip6ToBigint(spfAddress);
        BigInteger prefix = prefixToBigInt(spfPrefix);

        return hostIpNo.and(prefix).equals(spfAddressNo.and(prefix));
    }

    private static BigInteger ip6ToBigint(InetAddress addr){
        return new BigInteger(1,addr.getAddress());
    }

    private static BigInteger prefixToBigInt(String prefix){
        int pref = Integer.parseInt(prefix);

        if (pref == 0) {
            return BigInteger.ZERO;
        }

        // (1 << pref) - 1
        BigInteger ones = BigInteger.ONE.shiftLeft(pref).subtract(BigInteger.ONE);

        // Shift into position: fill high bits, zero low bits
        return ones.shiftLeft(128 - pref);
    }

}
