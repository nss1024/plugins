package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfUtils;


public class Ip4Command implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing IP4. Sender:"+spfContext.getSenderIp()+" Domain: "+mechanism.getDomain()+" Prefix: "+mechanism.getPrefix()+" Qualifier: "+mechanism.getQualifier());
        if (mechanism.getPrefix() == null) {
            if(SpfUtils.isIp4Match(spfContext.getSenderIp(),mechanism.getDomain())){
                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
        }else{
            if(SpfUtils.matchesCidr(spfContext.getSenderIp(),mechanism.getDomain(),mechanism.getPrefix())){
                System.out.println("CIDR match found!");
                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
        }

        return SpfResult.NONE;
    }
}
