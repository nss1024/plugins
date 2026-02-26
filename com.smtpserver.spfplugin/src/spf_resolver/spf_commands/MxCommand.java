package spf_resolver.spf_commands;

import spf_resolver.*;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MxCommand implements SpfCommand{

    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing MX");
        String domain = mechanism.getDomain();
        if (domain == null || domain.isEmpty()) {
            domain = spfContext.getDomain();
        }
        if(spfContext.alreadyVisited(mechanism)){
            return SpfResult.NONE;
        }else{
            spfContext.markVisited(mechanism);
        }
        spfContext.incrementLookups();
        if(spfContext.isMaxlookups()){
            return SpfResult.PERMERROR;
        }
        List<String> mxRecords;
        try {
            mxRecords = spfContext.getDnsService().getMxRecords(domain != null ? mechanism.getDomain() : spfContext.getDomain());
        }catch (SpfDnsException e){
            return SpfResult.TEMPERROR;
        }

        if(mxRecords==null||mxRecords.isEmpty()){
            mxRecords=new ArrayList<>();
            mxRecords.add(mechanism.getDomain());
        }
        if(mxRecords.size()>10){return SpfResult.PERMERROR;}

            //Need to retrieve A or AAAA for each record returned and check if sender IP matches.
            //Based on sender IP , only need to do either A or AAAA

            //set dns lookup type based on sender ip
            int dnsLookupType = SpfUtils.isIPv6(spfContext.getSenderIp())? 28:1;
            List<String> ipAddressList;
            for(String s:mxRecords){
                spfContext.incrementLookups();
                if(spfContext.isMaxlookups()){
                    return SpfResult.PERMERROR;
                }
                ipAddressList = spfContext.getDnsService().getDnsRecords(s,dnsLookupType);
                if(ipAddressList==null || ipAddressList.isEmpty()){continue;}
                for(String ip : ipAddressList){//evaluate each IP or CIDR
                    if (ip.isEmpty()) {
                        continue;
                    }
                        if(dnsLookupType==1) {//use IP4 evaluation
                            if(SpfUtils.isIp4Match(spfContext.getSenderIp(),ip)){
                                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());}
                        }else{//use IP6 evaluation
                            if (SpfUtils.isIp6Match(spfContext.getSenderIp(), ip)) {
                                return SpfUtils.getResultFromQualifier(mechanism.getQualifier());
                            }
                        }

                }

            }


        return SpfResult.NONE;
    }
}
