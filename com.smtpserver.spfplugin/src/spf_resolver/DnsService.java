package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Lookup;

import java.net.UnknownHostException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class DnsService {

    org.xbill.DNS.Lookup lookup = null;
    private int timeout = 5; // TODO: will need to come form config
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     *
     * @param domainName
     * @return Returns a String SPF record from the TXT record. This can be used as a String or
     * passed to the getMechanisms() method where it can be broken down to individual mechanism objects
     * for further processing.
     */
    public String getSpfRecords(String domainName){
        try {
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
            lookup = new org.xbill.DNS.Lookup(domainName, Type.TXT);
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

    /**
     *
     * @param domainName - the domain name for which to return A or AAAA records for
     * @param t - integer id for either A (1) ur AAAA (28) that the lookup should return
     * @return Returns a list of A or AAAA records for the domain provided
     *
     */
    public List<String> getDnsRecords(String domainName, int t) {

        if (!domainName.isEmpty()) {
            try {
                SimpleResolver resolver = new SimpleResolver();
                resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
                lookup = new org.xbill.DNS.Lookup(domainName,t);
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

    public List<String> getPtrRecords(String reverseAddr){
        if (!reverseAddr.isEmpty()) {
            try{
                SimpleResolver resolver = new SimpleResolver();
                resolver.setTimeout(Duration.of(timeout, ChronoUnit.SECONDS));
                lookup = new org.xbill.DNS.Lookup(reverseAddr, Type.PTR);
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

    public List<String> getMxRecords(String domainName){

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

    public List<SpfMechanism> getMechanisms (String spfTxt){
        List<SpfMechanism> result = new ArrayList<>();
        String[] splitSpf = spfTxt.split(" ");
        for(int i=1;i<splitSpf.length;i++){
            result.add(SpfUtils.getSpfMechanismFromString(splitSpf[i]));
        }
        return result;
    }

}
