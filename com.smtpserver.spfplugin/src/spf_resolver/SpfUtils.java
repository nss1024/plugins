package spf_resolver;

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SpfUtils {

        private SpfUtils(){}

    private static final Set<Character> QUALIFIERS = new HashSet<>(Arrays.asList('+','-','~','?'));

    private static int ipToInt(String ip){
        int result = 0;
        int shiftBy = 24;
        for (String s : ip.split("\\.")) {
            int octet = Integer.parseInt(s) & 0xff;
            result |= octet << shiftBy;
            shiftBy -= 8;
        }
        return result;
    }

    private static int prefixToMask(int prefix){
        if(prefix == 0) return 0;
        int result = -1; // -1 = 1111111111111111
        return result<< (32-prefix);

    }

    public static boolean matchesCidr(String ip, String cidr){
        int hostIp = ipToInt(ip);
        String[] parts = cidr.split("/");
        int spfIp = ipToInt(parts[0]);
        int mask = prefixToMask(Integer.parseInt(parts[1]));
        return (hostIp&mask)==(spfIp&mask);
    }

    public static boolean matchesCidr(String hostAddress, String spfAddress, int prefix){

        int hostIp = ipToInt(hostAddress);
        int spfIp = ipToInt(spfAddress);
        int mask = prefixToMask(prefix);
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

    public static boolean matchesIpv6Cidr(String hostIp, String spfIpAddress, String spfPrefix){
        InetAddress hostAddress, spfAddress = null;
        try {
            hostAddress = InetAddress.getByName(hostIp);
            spfAddress = InetAddress.getByName(spfIpAddress);

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

    public static boolean isIp6Match(String hostIp6, String spfIp6){
        InetAddress hostAddr = null;
        InetAddress spfAddr = null;
        try {
            hostAddr = InetAddress.getByName(hostIp6);
            spfAddr = InetAddress.getByName(spfIp6);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

          return hostAddr.equals(spfAddr);
    }

    public static boolean isIp4Match(String hostIp4, String spfIp4){
            return hostIp4.equals(spfIp4);
    }

    private static boolean isIpv4MappedAddress(InetAddress addr){
            if(!(addr instanceof Inet6Address)){
                return false;
            }

            byte[] bytes =addr.getAddress();

            byte[] b = addr.getAddress();
            //Check if array is 16 bytes
            if (b.length != 16) return false;

            // First 10 bytes must be zero, next 2 must be 0xFF
            for (int i = 0; i < 10; i++) {
                if (b[i] != 0) return false;
            }
            return (b[10] == (byte) 0xFF && b[11] == (byte) 0xFF);
    }

    public static String extractIp4FromIp6(InetAddress addr){
        if(!(addr instanceof Inet6Address)&& !isIpv4MappedAddress(addr)){
            return null;
        }
        byte[] bytes =addr.getAddress();
        return (bytes[12]&0xFF)+"."+(bytes[13]&0xFF)+"."+(bytes[14]&0xFF)+"."+(bytes[15]&0xFF);
    }

    private static SpfQualifier getQualifierFromString(String s){
        if (s == null || s.isEmpty()) return SpfQualifier.PASS;

        char c = s.charAt(0);

        switch (c) {
            case '+': return SpfQualifier.PASS;
            case '-': return SpfQualifier.FAIL;
            case '~': return SpfQualifier.SOFTFAIL;
            case '?': return SpfQualifier.NEUTRAL;
            default:  return SpfQualifier.PASS;
        }
    }

    private static SpfType getSpfTypeFromString(String s){
        String spfType="";
        if (s == null || s.isEmpty()) return null;
        final Set<Character> QUALIFIERS =new HashSet<>(Arrays.asList('+', '-', '~', '?'));
        if (QUALIFIERS.contains(s.charAt(0))) {
            s = s.substring(1);
        }
        if(s.contains(":")){
        spfType=s.substring(0,s.indexOf(":")).toLowerCase();
        }else{spfType=s;}
        switch (spfType) {
            case "include": return SpfType.INCLUDE;
            case "mx": return SpfType.MX;
            case "a": return SpfType.A;
            case "ip4": return SpfType.IP4;
            case "ip6": return SpfType.IP6;
            case "all": return SpfType.ALL;
            case "exists": return SpfType.EXISTS;
            case "ptr": return SpfType.PTR;
            default:  return SpfType.ALL;
        }
    }

    private static boolean hasSpfQualifier(String s){
        return QUALIFIERS.contains(s.charAt(0));
    }

    public static SpfMechanism getSpfMechanismFromString(String s){
        try {
            SpfQualifier qualifier = hasSpfQualifier(s) ? getQualifierFromString(s):SpfQualifier.PASS;
            SpfType type = getSpfTypeFromString(s);
            if(type.equals(SpfType.ALL)){
                return new SpfMechanism(qualifier,type,null,null);
            }
            Integer prefix = null;
            String domain = null;
            if (s.contains("/")) {
                prefix = Integer.valueOf(s.split("/")[1]);
                domain = s.substring(s.indexOf(":")+1, s.indexOf("/"));
            } else {
                domain = s.substring(s.indexOf(":")+1);
            }
            return new SpfMechanism(qualifier,type,domain,prefix);
        }catch (Exception e){
            System.out.println(e);
            return null;
        }

    }

    public static SpfResult getResultFromQualifier(SpfQualifier q){
        if (q == null) return SpfResult.PASS;

        switch (q) {
            case PASS: return SpfResult.PASS;
            case FAIL: return SpfResult.FAIL;
            case SOFTFAIL: return SpfResult.SOFTFAIL;
            case NEUTRAL: return SpfResult.NEUTRAL;
            default:  return SpfResult.PASS;
        }
    }

    public static String reverseIP4ToPtrAddress(String address){
        if(address==null){return null;}
        String addr[] = address.split("\\.");
        for (String part : addr) {
            int octet = Integer.parseInt(part);
            if (octet < 0 || octet > 255) return null;
        }
        if(addr.length==4){
        return  addr[3]+"."+addr[2]+"."+addr[1]+"."+addr[0]+".in-addr.arpa.";
        }else{
            return null;
        }
    }

    public static String reverseIP6ToPtrAddress(String address){
        InetAddress addr = null;
        try {
            addr = InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            return null;
        }
        byte[] bytes = addr.getAddress(); // 16 bytes

        StringBuilder sb = new StringBuilder();

        for (int i = bytes.length - 1; i >= 0; i--) {
            int b = bytes[i] & 0xff;
            sb.append(Integer.toHexString(b & 0x0f));
            sb.append('.');
            sb.append(Integer.toHexString((b >> 4) & 0x0f));
            sb.append('.');
        }

        sb.append("ip6.arpa.");
        return sb.toString();
    }

    public static boolean isIPv6(String ip){
        return ip.contains(":");
    }



}
