/*This happens to be RFC 7208 ..... funny that :)
 *
 */

import spf_resolver.Lookup;

import java.util.*;


public class Main {
    private static Map<String,List<String>> spfLists = new HashMap<>();


    public static void main(String[] args)
    {
        spfLists.put("ip4",new ArrayList<String>());
        spfLists.put("ip6",new ArrayList<String>());
        spfLists.put("includes",new ArrayList<String>());
        spfLists.put("aRecords",new ArrayList<String>());

        System.out.println("Hello, World!");
        Lookup lookup = new Lookup();
        lookup.start();
        lookup.lookupSpfRecord("nasstar.com");


    }
}