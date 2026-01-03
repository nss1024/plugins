package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfUtils;

public class Ip6Command implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        if (mechanism.getPrefix() == null) {
            if(SpfUtils.isIp6Match(spfContext.getSenderIp(),mechanism.getDomain())){
                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
        }else{
            if(SpfUtils.matchesIpv6Cidr(spfContext.getSenderIp(),mechanism.getDomain(),mechanism.getPrefix().toString())){
                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
        }
        return SpfResult.NONE;
    }
}
