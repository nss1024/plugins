package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;

import java.util.Collections;
import java.util.List;

public class IncludesCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing Includes");
        if(spfContext.getLookupCount()>=10){
            return SpfResult.PERMERROR;
        }
        spfContext.incrementLookups();
        String records = spfContext.getDnsService().getSpfRecords(mechanism.getDomain());
        if(records!=null) {
            List<SpfMechanism> newMechanismList = spfContext.getDnsService().getMechanisms(records);
            Collections.reverse(newMechanismList);
            spfContext.getWorkQueue().addAll(newMechanismList);
        }
        return SpfResult.NONE;
    }
}
