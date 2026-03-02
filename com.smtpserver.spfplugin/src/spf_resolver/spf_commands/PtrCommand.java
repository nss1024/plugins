package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfUtils;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.List;

public class PtrCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing PTR");

        String mechanismDomain = mechanism.getDomain();
        if (mechanismDomain == null || mechanismDomain.isEmpty()) {
            mechanismDomain = spfContext.getDomain();
        }

        spfContext.incrementLookups();
        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }

        String ptrAddr = SpfUtils.isIPv6(spfContext.getSenderIp())?SpfUtils.reverseIP6ToPtrAddress(spfContext.getSenderIp()):SpfUtils.reverseIP4ToPtrAddress(spfContext.getSenderIp());
        List<String> ptrLookupResult = null;
        if(ptrAddr!=null && !ptrAddr.isEmpty()) {
            try {
                ptrLookupResult = spfContext.getDnsService().getPtrRecords(ptrAddr);
                if(ptrLookupResult.size()>10){return SpfResult.PERMERROR;}
            }catch(SpfDnsException e){
                return SpfResult.TEMPERROR;
            }
        }
        if(ptrLookupResult!=null&&!ptrLookupResult.isEmpty()){
            int type=SpfUtils.isIPv6(spfContext.getSenderIp())?28:1;
            for(String s:ptrLookupResult){
                List<String> dnsLookupResult;
                try {
                    spfContext.incrementLookups();
                    if(spfContext.isMaxlookups()){
                        return SpfResult.PERMERROR;
                    }
                    dnsLookupResult = spfContext.getDnsService().getDnsRecords(s, type);
                }catch (SpfDnsException e){
                    return SpfResult.TEMPERROR;
                }
                if(dnsLookupResult!=null){
                    for(String dns:dnsLookupResult){
                        if(type==28){
                            if(SpfUtils.isIp6Match(spfContext.getSenderIp(),dns)&&isValidPtrDomainMatch(s,mechanismDomain)){return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
                        }else{
                            if(SpfUtils.isIp4Match(spfContext.getSenderIp(),dns)&&isValidPtrDomainMatch(s,mechanismDomain)){return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
                        }

                    }
                }
            }
        }
        return SpfResult.NONE;
    }

    private boolean isValidPtrDomainMatch(String host, String domain) {
        if (host == null || domain == null) return false;

        String h = host.toLowerCase();
        String d = domain.toLowerCase();

        return h.equals(d) || h.endsWith("." + d);
    }

}
