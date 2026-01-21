package spf_resolver.spf_commands;

import spf_resolver.*;

public class AllCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing all!");
        if(mechanism.getQualifier()== SpfQualifier.PASS){
            return SpfResult.PASS;
        }else if (spfContext.getWorkQueue().isEmpty()){
            return SpfUtils.getResultFromQualifier(mechanism.getQualifier());
        }
        return SpfResult.NONE;
    }
}
