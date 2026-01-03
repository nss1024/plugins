package spf_resolver.spf_commands;

import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;

public interface SpfCommand {

    SpfResult execute(SpfMechanism mechanism, SpfContext spfContext);

}
