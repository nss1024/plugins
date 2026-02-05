package spf_resolver.spf_commands;

import spf_resolver.*;

import java.util.ArrayDeque;
import java.util.List;

public class IncludesCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing Includes for: "+mechanism.getDomain());
        if(spfContext.getVisited().contains(mechanism.getDomain())){
            return SpfResult.NONE;
        }else{
            spfContext.getVisited().add(mechanism.getDomain());
        }
        if(spfContext.getLookupCount()>=10){
            return SpfResult.PERMERROR;
        }
        spfContext.incrementLookups();
        String records = spfContext.getDnsService().getSpfRecords(mechanism.getDomain());
        if(records!=null) {
            List<SpfMechanism> newMechanismList = spfContext.getDnsService().getMechanisms(records);
            SpfContext includeContext = new SpfContext(spfContext.getDomain(),spfContext.getSenderIp(),spfContext.getMaxLookups(),new ArrayDeque<>(newMechanismList), spfContext.getDnsService());
            SpfEvaluator evaluator = new SpfEvaluator();
            return evaluator.processIncludeSpfRecords(includeContext, spfContext);
        }
        return SpfResult.NONE;
    }
}
