package spf_resolver.spf_commands;

import spf_resolver.*;
import spf_resolver.spf_custom_exceptions.SpfDnsException;

import java.util.Collections;
import java.util.List;

public class MxCommand implements SpfCommand{

    @Override
    public SpfResult execute(SpfMechanism mechanism, SpfContext spfContext) {
        System.out.println("Processing MX");
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
            mxRecords = spfContext.getDnsService().getMxRecords(mechanism.getDomain() != null ? mechanism.getDomain() : spfContext.getDomain());
        }catch (SpfDnsException e){
            return SpfResult.TEMPERROR;
        }

        if(mxRecords!=null){

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
                if(ipAddressList==null){return SpfResult.NONE;}
                for(String ip : ipAddressList){//evaluate each IP or CIDR
                    if (ipAddressList.isEmpty()) {
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
        }

        return SpfResult.NONE;
    }
}
