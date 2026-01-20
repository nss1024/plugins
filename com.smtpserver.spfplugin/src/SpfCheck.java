import smtpSecurityApi.SecurityContext;
import smtpSecurityApi.SecurityPlugin;
import smtpSecurityApi.SecurityResult;
import spf_resolver.Lookup;
import spf_resolver.spf_commands.SpfCommandsRegister;

public class SpfCheck implements SecurityPlugin {


    @Override
    public SecurityResult execute(SecurityContext securityContext) {
        String domain = securityContext.get("domain").toString();
        String senderIp = securityContext.get("sender-ip").toString();
        Lookup lookup = new Lookup();
        lookup.start();
        lookup.lookupSpfRecord(domain,senderIp);
        return null;
    }
}
