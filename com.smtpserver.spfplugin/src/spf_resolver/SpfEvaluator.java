package spf_resolver;

import spf_resolver.spf_commands.SpfCommandsRegister;

public class SpfEvaluator {

    public SpfResult processSpfRecord(SpfContext context){
        SpfCommandsRegister commandsRegister = new SpfCommandsRegister();
        SpfMechanism tmp = null;

        if(!context.isQueueEmpty()){
            while(!context.isQueueEmpty()){
                tmp=context.getWorkQueue().pop();
                if(tmp.getType().equals(SpfType.ALL)){
                    return SpfUtils.getResultFromQualifier(tmp.getQualifier());}
                SpfResult result = commandsRegister.getCommand(tmp.getType().toString()).execute(tmp,context);
                if(result!=SpfResult.NONE){
                    return result;
                }
            }
        }
        return SpfResult.NONE;
    }

    public SpfResult processIncludeSpfRecords(SpfContext includeContext, SpfContext mainContext){
        SpfCommandsRegister commandsRegister = new SpfCommandsRegister();
        SpfMechanism tmp = null;

        if(!includeContext.isQueueEmpty()){
            while(!includeContext.isQueueEmpty()){
                if(includeContext.getLookupCount()+mainContext.getLookupCount()>mainContext.getMaxLookups()){
                    return SpfResult.PERMERROR;
                }
                tmp=includeContext.getWorkQueue().pop();

                if(tmp.getType().equals(SpfType.ALL)){
                    mainContext.incrementLookupsBy(includeContext.getLookupCount());
                    return SpfResult.NONE;}
                SpfResult result = commandsRegister.getCommand(tmp.getType().toString()).execute(tmp,includeContext);
                if(result!=SpfResult.NONE){
                    return result;
                }
            }
        }
        return SpfResult.NONE;
    }

}
