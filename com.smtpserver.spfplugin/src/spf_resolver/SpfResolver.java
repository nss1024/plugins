package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spf_resolver.spf_custom_exceptions.SpfParseException;

import java.util.*;
import java.util.concurrent.Callable;


public class SpfResolver implements Callable<SpfResult> {

    String domainName;
    org.xbill.DNS.Lookup lookup = null;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private int timeout = 5;
    private String senderIp;
    private final int MAX_LOOKUPS=10;
    DnsService dnsService=new DnsService();

    public SpfResolver(String domainName, String senderIp, int lookupTimeout){
        this.domainName=domainName;
        this.timeout=lookupTimeout;
        this.senderIp=senderIp;

    }

    @Override
    public SpfResult call() throws Exception {

        String spfText = dnsService.getSpfRecords(domainName);
        List<SpfMechanism> mechanisms=null;
        SpfContext context = null;
        if(spfText!=null){
            System.out.println("Spf text: "+spfText);
            try {
                mechanisms = dnsService.getMechanisms(spfText);
            }catch (SpfParseException e){
                return SpfResult.PERMERROR;
            }
            System.out.println("Generated mechanisms :"+Arrays.toString(mechanisms.toArray()));
        }

        if(mechanisms!=null){
            context = new SpfContext(domainName,senderIp,MAX_LOOKUPS,new ArrayDeque<>(mechanisms), dnsService);
        }

        if(context!=null){
            SpfEvaluator spfEvaluator = new SpfEvaluator();
          return  spfEvaluator.processSpfRecord(context);
        }

        return SpfResult.NONE;
    }


}
