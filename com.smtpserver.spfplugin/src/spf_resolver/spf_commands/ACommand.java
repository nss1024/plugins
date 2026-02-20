package spf_resolver.spf_commands;

import org.xbill.DNS.Type;
import spf_resolver.*;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.Collections;
import java.util.List;

public class ACommand implements SpfCommand{
    private List<String> ipList=null;


    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing A");
        if(spfContext.alreadyVisited(mechanism)){
            return SpfResult.NONE;
        }else{
            spfContext.markVisited(mechanism);
        }
        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }

        if(spfContext.alreadyVisited(mechanism)){
            return SpfResult.NONE;
        }
        spfContext.incrementLookups();
        spfContext.alreadyVisited(mechanism);
        try {
            ipList = spfContext.getDnsService().getDnsRecords(mechanism.getDomain(), Type.A);
        }catch (SpfDnsException e){
            return SpfResult.TEMPERROR;
        }
        if(ipList!=null){

            for(String ip:ipList){

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
