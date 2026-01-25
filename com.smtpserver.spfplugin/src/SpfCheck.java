import smtpSecurityApi.SecurityContext;
import smtpSecurityApi.SecurityPlugin;
import smtpSecurityApi.SecurityResult;
import spf_resolver.Lookup;
import spf_resolver.SpfResult;


import java.util.concurrent.ExecutionException;

public class SpfCheck implements SecurityPlugin {


    @Override
    public SecurityResult execute(SecurityContext securityContext) {
        String domain = securityContext.get("domain").toString();
        String senderIp = securityContext.get("sender-ip").toString();
        Lookup lookup = new Lookup();
        lookup.start();
        SpfResult result;
        try {
            result = lookup.lookupSpfRecord(domain,senderIp).get();
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
           //TODO add log + appropriate return
            result=SpfResult.TEMPERROR;

        }

        return mapSpfToSecurity(result);
    }

    public SecurityResult mapSpfToSecurity(SpfResult spf) {
         switch (spf) {
            case PASS : return SecurityResult.ALLOW;
             case FAIL :
             case PERMERROR :
                 return SecurityResult.DENY;
             case SOFTFAIL : return SecurityResult.QUARANTINE;
             case NEUTRAL :
             case NONE :
                 return SecurityResult.RULE_MATCHED;
             case TEMPERROR : return SecurityResult.TEMPORARY_REJECT;
             default: return SecurityResult.QUARANTINE;
         }
    }

}
