package spf_resolver.spf_commands;

import org.xbill.DNS.Type;
import spf_resolver.*;

import java.util.Collections;
import java.util.List;

public class AAAACommand implements SpfCommand{
    DnsService dnsService=new DnsService();

    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        if(spfContext.getLookupCount()>=10){
            return SpfResult.PERMERROR;
        }
        if(spfContext.alreadyVisited(mechanism)){
            return SpfResult.NONE;
        }
        spfContext.incrementLookups();
        spfContext.alreadyVisited(mechanism);

        List<String> ipList = dnsService.getDnsRecords(mechanism.getDomain(), Type.AAAA);
        if(ipList !=null){
            Collections.reverse(ipList);
            for(String ip: ipList){
                spfContext.getWorkQueue().add(
                        new SpfMechanism(
                                mechanism.getQualifier(),
                                SpfType.IP4,
                                ip,
                                null
                        )
                );
            }
        }
        return SpfResult.NONE;
    }
}
