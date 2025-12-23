package spf_resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Lookup {
    private int numberOfthreads = 4;
    private ExecutorService lookupThreadPool;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public Lookup(){

    }

    public void start(){
        lookupThreadPool= Executors.newFixedThreadPool(numberOfthreads);
    }

    public Future<SpfResult> lookupSpfRecord(String domainName){
        if(lookupThreadPool!=null){
            return lookupThreadPool.submit(new SpfResolver(domainName,5));
        }
        return null;
    }

    public void shutdown() {
        if (lookupThreadPool != null) {
            lookupThreadPool.shutdown();
        }
    }
}
