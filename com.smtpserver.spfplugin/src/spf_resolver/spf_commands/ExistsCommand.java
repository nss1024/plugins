package spf_resolver.spf_commands;

import org.xbill.DNS.Type;
import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfUtils;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.List;

public class ExistsCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing Exists!");
        if (mechanism.getDomain() == null || mechanism.getDomain().isEmpty()) {
            return SpfResult.PERMERROR;
        }

        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }
        spfContext.incrementLookups();
        List<String> ipList;
        try {
            ipList = spfContext.getDnsService().getDnsRecords(mechanism.getDomain(), Type.A);
        }catch (SpfDnsException e){
            return  SpfResult.TEMPERROR;
        }
        if(ipList.isEmpty()||ipList==null){
            return SpfResult.NONE;
        }
        else{
            return SpfUtils.getResultFromQualifier(mechanism.getQualifier());
        }
    }
}
