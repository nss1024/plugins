package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;
import spf_resolver.SpfType;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.Collections;
import java.util.List;

public class MxCommand implements SpfCommand{

    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing MX");
        if(spfContext.getVisited().contains(mechanism.getDomain())){
            return SpfResult.NONE;
        }else{
            spfContext.getVisited().add(mechanism.getDomain());
        }
        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }
        if(spfContext.alreadyVisited(mechanism)){
         return SpfResult.NONE;
        }
        spfContext.incrementLookups();
        List<String> mxRecords;
        try {
            mxRecords = spfContext.getDnsService().getMxRecords(mechanism.getDomain() != null ? mechanism.getDomain() : spfContext.getDomain());
        }catch (SpfDnsException e){
            return SpfResult.TEMPERROR;
        }
        spfContext.alreadyVisited(mechanism);
        if(mxRecords!=null){
            Collections.reverse(mxRecords);
            for(String s:mxRecords){
                spfContext.getWorkQueue().add(
                        new SpfMechanism(
                                mechanism.getQualifier(),
                                SpfType.A,
                                s,
                                null
                        )
                );
            }
        }

        return SpfResult.NONE;
    }
}
