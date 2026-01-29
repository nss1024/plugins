package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Lookup;
import spf_resolver.spf_commands.SpfCommandsRegister;


import java.net.UnknownHostException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.Callable;


public class SpfResolver implements Callable<SpfResult> {

    String domainName;
    org.xbill.DNS.Lookup lookup = null;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private int lookupCounter = 0;// count number of dns lookups performed
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
            mechanisms=dnsService.getMechanisms(spfText);
            System.out.println("Generated mechanisms :"+Arrays.toString(mechanisms.toArray()));
        }

        if(mechanisms!=null){
            context = new SpfContext(domainName,senderIp,MAX_LOOKUPS,new ArrayDeque<>(mechanisms));
        }

        if(context!=null){

          return  processSpfRecord(context);
        }

        return null;
    }

    private SpfResult processSpfRecord(SpfContext context){
        SpfCommandsRegister commandsRegister = new SpfCommandsRegister();
        SpfMechanism tmp = null;

        if(!context.isQueueEmpty()){
            while(!context.isQueueEmpty()){
                tmp=context.getWorkQueue().pop();
                if(tmp.getType().equals(SpfType.ALL)){
                    return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                SpfResult result = commandsRegister.getCommand(tmp.getType().toString()).execute(tmp,context);
                if(result!=SpfResult.NONE){
                    return result;
                    }
            }
        }
        return null;
    }


}
