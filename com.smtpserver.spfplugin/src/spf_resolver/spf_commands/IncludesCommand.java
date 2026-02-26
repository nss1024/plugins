package spf_resolver.spf_commands;

import spf_resolver.*;

import java.util.ArrayDeque;
import java.util.List;

public class IncludesCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing Includes for: "+mechanism.getDomain());
        if(spfContext.alreadyVisited(mechanism)){
            return SpfResult.PERMERROR;
        }else{
            spfContext.markVisited(mechanism);
        }
        spfContext.incrementLookups();
        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }

        String records = spfContext.getDnsService().getSpfRecords(mechanism.getDomain());
        if(records==null){return SpfResult.PERMERROR;}

            List<SpfMechanism> newMechanismList = spfContext.getDnsService().getMechanisms(records);
            if(newMechanismList==null){return SpfResult.PERMERROR;}
            SpfContext includeContext = new SpfContext(mechanism.getDomain(),spfContext.getSenderIp(),spfContext.getMaxLookups(),new ArrayDeque<>(newMechanismList), spfContext.getDnsService());
            SpfEvaluator evaluator = new SpfEvaluator();
            SpfResult result = evaluator.processIncludeSpfRecords(includeContext, spfContext);
            if (result == SpfResult.PASS) {
                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());
            }
            if (result == SpfResult.TEMPERROR) return SpfResult.TEMPERROR;
            if (result == SpfResult.PERMERROR) return SpfResult.PERMERROR;

        return SpfResult.NONE;
    }
}
