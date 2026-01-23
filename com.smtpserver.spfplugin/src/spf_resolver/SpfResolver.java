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

    public SpfResolver(String domainName, String senderIp, int lookupTimeout){
        this.domainName=domainName;
        this.timeout=lookupTimeout;
        this.senderIp=senderIp;

    }

    @Override
    public SpfResult call() throws Exception {

        //List<SpfMechanism> spfMechanism=null;
        //String testSenderIp="86.111.216.2";
        //String spfRecord = getSpfRecords(domanName);
        //if(spfRecord!=null) {
        //    spfMechanism = getMechanisms(spfRecord);
        //}
        //System.out.println("Spf record: "+spfRecord);
        //System.out.println("IP list from DNS lookup: "+Arrays.toString(getDnsRecords("b.spf.service-now.com",Type.A).toArray()));
        //System.out.println("Mx records: "+Arrays.toString(getMxRecords("nasstar.com").toArray()));
        //for(SpfMechanism sm:spfMechanism){
        //    System.out.println(sm.toString());
        //}
        //System.out.println("-----------**--------------------");
        //System.out.println(processSpfRecords(spfMechanism,spfStack,testSenderIp));

        //System.out.println(Arrays.toString(getPtrRecords("8.8.8.8.in-addr.arpa.").toArray()));
        String spfText = getSpfRecords(domainName);
        List<SpfMechanism> mechanisms=null;
        SpfContext context = null;
        if(spfText!=null){
            mechanisms=getMechanisms(spfText);
        }
        if(mechanisms!=null){
            context = new SpfContext(domainName,senderIp,MAX_LOOKUPS,new ArrayDeque<>(mechanisms));
        }

        if(context!=null){
          return  processSpfRecord(context);
        }

        return null;
    }
    //get SPF records for a domain
    private String getSpfRecords(String domainName){
        try {
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
            lookup = new Lookup(domainName, Type.TXT);
        } catch (TextParseException | UnknownHostException e) {
            logger.warn("Could not look up mx record!");
            return null;
        }
        Record[] records = lookup.run();
        if(records != null) {
           List<String> fragments;
            for (Record r : records) {
                if(r instanceof TXTRecord){
                    fragments=((TXTRecord) r).getStrings();
                    for(String f : fragments) {
                        if (f.contains("v=spf")) {
                            return String.join("",fragments);
                        }
                    }
                }
            }
        }
        return null;
    }

    //get all IP addresses for a given domain name, used to look up "a:" mechanism
    //A = 1; AAAA=28
    private List<String> getDnsRecords(String domainName, int t) {

        if (!domainName.isEmpty()) {
            try {
                SimpleResolver resolver = new SimpleResolver();
                resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
                lookup = new Lookup(domainName,t);
                lookup.setResolver(resolver);

            } catch (TextParseException | UnknownHostException e) {
                logger.warn("Could not look up domain for : {} !",domainName);
                return null;
            }

            Record[] aRecords = lookup.run();
            if (aRecords != null) {
                List<String> ipList = new ArrayList<>();
                for (Record rec : aRecords) {
                    ARecord a = (ARecord) rec;
                    ipList.add(a.getAddress().getHostAddress());
                }
                return ipList;
            }

        }
        return null;
    }

    private List<String> getPtrRecords(String reverseAddr){
        if (!reverseAddr.isEmpty()) {
            try{
                SimpleResolver resolver = new SimpleResolver();
                resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
                lookup = new Lookup(reverseAddr, Type.PTR);
                lookup.setResolver(resolver);
            } catch (TextParseException | UnknownHostException e) {
                logger.warn("Could not look up PTR record");
                return null;
            }
        }

        Record[] records = lookup.run();
        if(records != null) {
            List<String> recordslist=new ArrayList<>();
            for (Record r : records) {
                PTRRecord ptr = (PTRRecord) r;
                String host = ptr.getTarget().toString(true);
                recordslist.add(host);
            }
            return recordslist;
        }
        return null;
    }

    private List<String> getMxRecords(String domainName){

        try {
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
            lookup = new Lookup(domainName, Type.MX);
            lookup.setResolver(resolver);
        } catch (TextParseException | UnknownHostException e) {
            logger.warn("Could not look up mx record!");
            return null;
        }
        Record[] records = lookup.run();

        if(records != null) {
            List<String> recordslist=new ArrayList<>();
            for (Record r : records) {
                MXRecord mx = (MXRecord) r;
                String host = mx.getTarget().toString(true);
                if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
                recordslist.add(host);
            }
            return recordslist;
        }
        return null;
    }

    private List<SpfMechanism> getMechanisms (String spfTxt){
        List<SpfMechanism> result = new ArrayList<>();
        String[] splitSpf = spfTxt.split(" ");
        for(int i=1;i<splitSpf.length;i++){
            result.add(SpfUtils.getSpfMechanismFromString(splitSpf[i]));
        }
        return result;
    }

    private SpfResult processSpfRecords(List<SpfMechanism> spfMechanisms,Stack<SpfMechanism> spfStack, String senderIp){
        SpfMechanism tmp = null;
        List<String>ipList=null;
        spfStack.addAll(spfMechanisms);
        if(!spfStack.isEmpty()) {
            while (!spfStack.isEmpty() && lookupCounter <= 10) {
                tmp=spfStack.pop();
                switch(tmp.getType()){
                    case IP4:
                        if (tmp.getPrefix() == null) {
                            if(SpfUtils.isIp4Match(senderIp,tmp.getDomain())){return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                        }else{
                            if(SpfUtils.matchesCidr(senderIp,tmp.getDomain(),tmp.getPrefix())){return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                        }
                        break;
                    case IP6:
                        if (tmp.getPrefix() == null) {

                            if(SpfUtils.isIp6Match(senderIp,tmp.getDomain())){return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                        }else{

                            if(SpfUtils.matchesIpv6Cidr(senderIp,tmp.getDomain(),tmp.getPrefix().toString())){return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                        }
                        break;
                    case A:
                        if(lookupCounter>=10){
                            return SpfResult.PERMERROR;
                        }
                        lookupCounter++;
                        ipList = getDnsRecords(tmp.getDomain(),Type.A);
                        if(ipList!=null){
                            Collections.reverse(ipList);
                            for(String ip:ipList){
                                spfStack.add(
                                        new SpfMechanism(
                                                tmp.getQualifier(),
                                                SpfType.IP4,
                                                ip,
                                                null
                                        )
                                );
                            }
                        }
                        break;
                    case INCLUDE:
                        if(lookupCounter>=10){
                            return SpfResult.PERMERROR;
                        }
                        lookupCounter++;
                        String records = getSpfRecords(tmp.getDomain());
                        if(records!=null) {
                            List<SpfMechanism> newMechanismList = getMechanisms(records);
                            Collections.reverse(newMechanismList);
                            spfStack.addAll(newMechanismList);
                        }
                        break;
                    case MX:
                        if(lookupCounter>=10){
                            return SpfResult.PERMERROR;
                        }
                        lookupCounter++;
                        List<String> mxRecords = getMxRecords(tmp.getDomain() != null ? tmp.getDomain() : domainName);
                        if(mxRecords!=null){
                            Collections.reverse(mxRecords);
                            for(String s:mxRecords){
                                spfStack.add(
                                        new SpfMechanism(
                                                tmp.getQualifier(),
                                                SpfType.A,
                                                s,
                                                null
                                        )
                                );
                            }
                        }
                        break;
                    case ALL:
                        if(tmp.getQualifier()==SpfQualifier.PASS){
                            return SpfResult.PASS;
                        }else if (spfStack.isEmpty()){
                            return SpfUtils.getResultFromQualifier(tmp.getQualifier());
                        }
                        break;

                    case EXISTS:
                        if(lookupCounter>=10){
                            return SpfResult.PERMERROR;
                        }
                        lookupCounter++;
                        ipList = getDnsRecords(tmp.getDomain(),Type.A);
                        if(ipList==null){break;}
                        else{
                            return SpfUtils.getResultFromQualifier(tmp.getQualifier());
                        }
                    case PTR://Implementation, will match if sender IP has at least 1 PTR record & PTR hostname resolves back to sender IP, either match or continue
                        if(lookupCounter>=10){
                            return SpfResult.PERMERROR;
                        }
                        lookupCounter++;
                        String ptrAddr = SpfUtils.isIPv6(senderIp)?SpfUtils.reverseIP6ToPtrAddress(senderIp):SpfUtils.reverseIP4ToPtrAddress(senderIp);
                        List<String> ptrLookupResult = null;
                        if(ptrAddr!=null) {
                            ptrLookupResult = getPtrRecords(ptrAddr);
                        }
                        if(ptrLookupResult!=null){
                            for(String s:ptrLookupResult){
                                int type=SpfUtils.isIPv6(senderIp)?28:1;
                              List<String> dnsLookupResult= getDnsRecords(s,type);
                                if(dnsLookupResult!=null){
                                    for(String dns:dnsLookupResult){
                                        if(SpfUtils.isIPv6(dns)){
                                            if(SpfUtils.isIp6Match(senderIp,dns)){return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                                        }else{
                                            if(SpfUtils.isIp4Match(senderIp,dns)){return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                                        }

                                    }
                                }
                            }
                        }
                        break;
                }

            }
        }
        return SpfResult.NEUTRAL;
    }

    private SpfResult processSpfRecord(SpfContext context){
        SpfCommandsRegister commandsRegister = new SpfCommandsRegister();
        SpfMechanism tmp = null;

        if(!context.isQueueEmpty()){
            while(!context.isQueueEmpty()){
                tmp=context.getWorkQueue().pop();
                //handle ALL - there may be many ALLs as the Includes mechanisms are flattened in the queue, only return a result if it's the last ALL in the queue
                if(tmp.getType().equals(SpfType.ALL)&&context.isQueueEmpty()){
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
