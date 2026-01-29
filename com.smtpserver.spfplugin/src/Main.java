/*This happens to be RFC 7208 ..... funny that :)
 *
 */

import smtpSecurityApi.SecurityContext;
import smtpSecurityApi.SecurityResult;
import spf_resolver.Lookup;
import spf_resolver.SpfUtils;

import java.util.*;


public class Main {



    public static void main(String[] args)
    {
        System.out.println("Hello, World!");
        SecurityContext sc = new SecurityContext();
        //sc.set("domain","gmail.com");
        sc.set("domain","nasstar.com");
        sc.set("sender-ip","89.111.216.1");
        //sc.set("sender-ip","83.165.115.0");//253.165.115.0
        SpfCheck spfCheck = new SpfCheck();
        SecurityResult result = spfCheck.execute(sc);
        System.out.println("Security result: "+result);

    }
}