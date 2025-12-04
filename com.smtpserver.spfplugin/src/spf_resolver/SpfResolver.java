package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Lookup;

import java.util.List;
import java.util.concurrent.Callable;

public class SpfResolver implements Callable<SpfReult> {

    String domanName;
    org.xbill.DNS.Lookup lookup = null;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public SpfResolver(String domainName){
        this.domanName=domainName;

    }

    @Override
    public SpfReult call() throws Exception {
        String spfRecords[]=null;
        String spfRecord = getSpfRecords(domanName);
        if(spfRecord!=null) {
            spfRecords = getMechanisms(spfRecord);
        }
        System.out.println("Spf record: "+spfRecord);
        getDnsRecords("b.spf.service-now.com");
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
    private void getDnsRecords(String domainName) {
        if (!domainName.isEmpty()) {
            try {

                lookup = new Lookup(domainName, Type.A);

            } catch (TextParseException e) {
                logger.warn("Could not look up domain for : {} !",domainName);
            }

            Record[] aRecords = lookup.run();
            if (aRecords != null) {
                for (Record rec : aRecords) {
                    ARecord a = (ARecord) rec;
                    System.out.println("A record :" +a);

                }
            }

        }
    }

    private String[] getMechanisms (String spfTxt){
        return spfTxt.split(" ");
    }

}
