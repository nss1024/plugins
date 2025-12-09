package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Lookup;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

public class SpfResolver implements Callable<SpfResult> {

    String domanName;
    org.xbill.DNS.Lookup lookup = null;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    //Queue<String> spfQueue = new

    public SpfResolver(String domainName){
        this.domanName=domainName;

    }

    @Override
    public SpfResult call() throws Exception {
        List<SpfMechanism> spfMechanism=null;
        String spfRecord = getSpfRecords(domanName);
        if(spfRecord!=null) {
            spfMechanism = getMechanisms(spfRecord);
        }
        System.out.println("Spf record: "+spfRecord);
        System.out.println(Arrays.toString(getDnsRecords("b.spf.service-now.com",Type.A).toArray()));
        System.out.println(Arrays.toString(getMxRecords("nasstar.com").toArray()));
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
        for(String s:splitSpf){
            if(s.startsWith("includes")){
                result.add(
                        new SpfMechanism(SpfMechanism.Qualifier.PASS,SpfMechanism.Type.INCLUDE,s.substring(result.indexOf(":")+1),null)
                );
            }
        }
        return null;
    }

}
