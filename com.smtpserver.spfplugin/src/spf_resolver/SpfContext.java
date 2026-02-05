package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class SpfContext {


    private final String domain;
    private final String senderIp;
    private final int maxLookups;


    private int lookupCount = 0;
    private final Deque<SpfMechanism> workQueue;
    private final Set<String> visited = new HashSet<>();
    private boolean redirectApplied=false;



    // Outcome
    private SpfResult result = null;

    private final DnsService dnsService;

    public SpfContext(String domain, String senderIp, int maxLookups, Deque<SpfMechanism> workQueue, DnsService dnsService) {
        this.domain = domain;
        this.senderIp = senderIp;
        this.maxLookups = maxLookups;
        this.workQueue = workQueue;
        this.dnsService=dnsService;
    }


    public void incrementLookups() {
        lookupCount++;
    }

    public void incrementLookupsBy(int count) {
        lookupCount+=count;
    }

    public boolean isMaxlookups(){
        return lookupCount>=maxLookups;
    }

    public boolean hasResult() {
        return result != null;
    }

    public void setResult(SpfResult result) {
        this.result = result;
    }

    public String getDomain() {
        return domain;
    }

    public String getSenderIp() {
        return senderIp;
    }

    public int getMaxLookups() {
        return maxLookups;
    }

    public int getLookupCount() {
        return lookupCount;
    }

    public Deque<SpfMechanism> getWorkQueue() {
        return workQueue;
    }

    public Set<String> getVisited() {
        return visited;
    }

    public SpfResult getResult() {
        return result;
    }

    public DnsService getDnsService() {
        return dnsService;
    }

    public boolean alreadyVisited(SpfMechanism mechanism) {
        String key = mechanism.getType() + ":" + mechanism.getDomain();
        return visited.contains(key);
    }

    public boolean markVisited(SpfMechanism mechanism) {
        String key = mechanism.getType() + ":" + mechanism.getDomain();
        return visited.add(key);
    }

    public boolean isQueueEmpty(){
        return workQueue.isEmpty();
    }

    public SpfResult applyRedirect(List<SpfMechanism> newMechanisms){
        if(redirectApplied){return SpfResult.PERMERROR;}
        redirectApplied=true;
        pushMechanisms(newMechanisms);
        return SpfResult.NONE;
    }

    private void pushMechanisms(List<SpfMechanism> newMechanisms){
            workQueue.clear();
            workQueue.addAll(newMechanisms);
    }

}
