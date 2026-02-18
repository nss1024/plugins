package spf_resolver.spf_commands;

import spf_resolver.*;

public class AllCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing all!");
        return SpfUtils.getResultFromQualifier(mechanism.getQualifier());

    }
}
