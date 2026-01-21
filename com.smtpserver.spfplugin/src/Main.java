/*This happens to be RFC 7208 ..... funny that :)
 *
 */

import smtpSecurityApi.SecurityContext;
import spf_resolver.Lookup;

import java.util.*;


public class Main {



    public static void main(String[] args)
    {
        System.out.println("Hello, World!");
        SecurityContext sc = new SecurityContext();
        sc.set("domain","nasstar.com");
        sc.set("sender-ip","6.111.216.2");
        SpfCheck spfCheck = new SpfCheck();
        spfCheck.execute(sc);
    }
}