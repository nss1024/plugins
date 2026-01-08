package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfUtils;

import java.util.List;

public class PtrCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        if(spfContext.getLookupCount()>=10){
            return SpfResult.PERMERROR;
        }
        spfContext.incrementLookups();
        String ptrAddr = SpfUtils.isIPv6(spfContext.getSenderIp())?SpfUtils.reverseIP6ToPtrAddress(spfContext.getSenderIp()):SpfUtils.reverseIP4ToPtrAddress(spfContext.getSenderIp());
        List<String> ptrLookupResult = null;
        if(ptrAddr!=null) {
            ptrLookupResult = spfContext.getDnsService().getPtrRecords(ptrAddr);
        }
        if(ptrLookupResult!=null){
            for(String s:ptrLookupResult){
                int type=SpfUtils.isIPv6(spfContext.getSenderIp())?28:1;
                List<String> dnsLookupResult= spfContext.getDnsService().getDnsRecords(s,type);
                if(dnsLookupResult!=null){
                    for(String dns:dnsLookupResult){
                        if(SpfUtils.isIPv6(dns)){
                            if(SpfUtils.isIp6Match(spfContext.getSenderIp(),dns)){return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
                        }else{
                            if(SpfUtils.isIp4Match(spfContext.getSenderIp(),dns)){return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
                        }

                    }
                }
            }
        }
        return SpfResult.NONE;
    }
}
