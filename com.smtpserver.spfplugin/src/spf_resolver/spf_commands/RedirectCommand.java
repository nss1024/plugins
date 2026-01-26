/*Notes: Redirect grabs the spf record of another domain and replaces the remaining records in the current evaluation.
 *Ony 1 redirect is allowed
 *
 */

package spf_resolver.spf_commands;
import spf_resolver.SpfContext;
import spf_resolver.SpfMechanism;
import spf_resolver.SpfResult;

import java.util.Arrays;
import java.util.List;
//TODO:  Only 1 redirect allowed, need to enforce !
public class RedirectCommand implements SpfCommand{
    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {

        String redirectSpfRecord = spfContext.getDnsService().getSpfRecords(mechanism.getDomain());
        List<SpfMechanism> newMechanisms = spfContext.getDnsService().getMechanisms(redirectSpfRecord);

        System.out.println("Redirect command new mechanisms: "+ Arrays.toString(newMechanisms.toArray()));

        return null;
    }
}
