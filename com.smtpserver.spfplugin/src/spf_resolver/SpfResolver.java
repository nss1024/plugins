package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Lookup;


import java.util.*;
import java.util.concurrent.Callable;


public class SpfResolver implements Callable<SpfResult> {

    String domanName;
    org.xbill.DNS.Lookup lookup = null;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private int lookupCounter = 0;// count number of dns lookups performed
    private Set<SpfMechanism> visited = new HashSet<>();//domains and IPs already checked
    private Stack<SpfMechanism> spfStack = new Stack<>();

    public SpfResolver(String domainName){
        this.domanName=domainName;

    }

    @Override
    public SpfResult call() throws Exception {
        List<SpfMechanism> spfMechanism=null;
        String testSenderIp="86.111.216.2";
        String spfRecord = getSpfRecords(domanName);
        if(spfRecord!=null) {
            spfMechanism = getMechanisms(spfRecord);
        }
        System.out.println("Spf record: "+spfRecord);
        System.out.println("IP list from DNS lookup: "+Arrays.toString(getDnsRecords("b.spf.service-now.com",Type.A).toArray()));
        System.out.println("Mx records: "+Arrays.toString(getMxRecords("nasstar.com").toArray()));
        for(SpfMechanism sm:spfMechanism){
            System.out.println(sm.toString());
        }
        System.out.println("-----------**--------------------");
        System.out.println(processSpfRecords(spfMechanism,spfStack,testSenderIp));


        return null;
    }
    //get SPF records for a domain
    private String getSpfRecords(String domainName){
        try {
            lookup = new org.xbill.DNS.Lookup(domainName, Type.TXT);
        } catch (TextParseException e) {
            logger.warn("Could not look up mx record!");
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
    private List<String> getDnsRecords(String domainName, int t) {

        if (!domainName.isEmpty()) {
            try {
                lookup = new Lookup(domainName,t);

            } catch (TextParseException e) {
                logger.warn("Could not look up domain for : {} !",domainName);
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

    private List<String> getMxRecords(String domainName){

        try {
            lookup = new Lookup(domainName, Type.MX);
        } catch (TextParseException e) {
            logger.warn("Could not look up mx record!");
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
        int length = spfMechanisms.size();
        Collections.reverse(spfMechanisms);
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
                        List<String>ipList = getDnsRecords(tmp.getDomain(),Type.A);
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
                        List<String> mxRecords = getMxRecords(domanName);
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
                }

            }
        }
        return null;
    }


}
