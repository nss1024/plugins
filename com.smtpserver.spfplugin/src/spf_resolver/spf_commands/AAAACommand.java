package spf_resolver.spf_commands;

import org.xbill.DNS.Type;
import spf_resolver.*;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.Collections;
import java.util.List;

public class AAAACommand implements SpfCommand{

    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing AAAA");
        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }
        if(spfContext.alreadyVisited(mechanism)){
            return SpfResult.NONE;
        }
        spfContext.incrementLookups();
        spfContext.markVisited(mechanism);
        List<String> ipList;
        try {
            ipList = spfContext.getDnsService().getDnsRecords(mechanism.getDomain(), Type.AAAA);
        }catch(SpfDnsException e){
            return  SpfResult.TEMPERROR;
        }
        if(ipList !=null){
            for(String ip: ipList){
                spfContext.getWorkQueue().add(
                        new SpfMechanism(
                                mechanism.getQualifier(),
                                SpfType.IP6,
                                ip,
                                null
                        )
                );
            }
        }
        return SpfResult.NONE;
    }
}
