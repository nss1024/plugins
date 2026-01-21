package spf_resolver.spf_commands;

import org.xbill.DNS.Type;
import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfUtils;

import java.util.List;

public class ExistsCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing Exists!");
        if(spfContext.getLookupCount()>=10){
            return SpfResult.PERMERROR;
        }
        spfContext.incrementLookups();
        List<String> ipList = spfContext.getDnsService().getDnsRecords(mechanism.getDomain(), Type.A);
        if(ipList==null){
            return SpfResult.NONE;
        }
        else{
            return SpfUtils.getResultFromQualifier(mechanism.getQualifier());
        }
    }
}
