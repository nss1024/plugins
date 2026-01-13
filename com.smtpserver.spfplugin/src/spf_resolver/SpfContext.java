package spf_resolver;

import java.util.*;

public class SpfContext {


    private final String domain;
    private final String senderIp;
    private final int maxLookups;


    private int lookupCount = 0;
    private final Deque<SpfMechanism> workQueue;
    private final Set<String> visited = new HashSet<>();

    // Outcome
    private SpfResult result = null;

    DnsService dnsService;

    public SpfContext(String domain, String senderIp, int maxLookups, Deque<SpfMechanism> workQueue) {
        this.domain = domain;
        this.senderIp = senderIp;
        this.maxLookups = maxLookups;
        this.workQueue = workQueue;
        dnsService=new DnsService();
    }


    public void incrementLookups() {
        lookupCount++;
    }

    public boolean isMaxlookups(){
        return lookupCount==maxLookups;
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

}
