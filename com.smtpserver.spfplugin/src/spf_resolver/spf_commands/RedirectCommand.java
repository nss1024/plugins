package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;

public class RedirectCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {

        System.out.println("Redirect command: "+mechanism.toString());

        return null;
    }
}
