package spf_resolver.spf_commands;


import java.util.HashMap;
import java.util.Map;

public class SpfCommandsRegister {

    Map<String, SpfCommand> commandsMap = new HashMap<>();

    public SpfCommandsRegister(){
        loadCommands();
    }

    public SpfCommand getCommand(String command){
        if(commandsMap!=null && !commandsMap.isEmpty()){
            return commandsMap.get(command.toUpperCase());
        }else{
            loadCommands();
            return commandsMap.get(command.toUpperCase());
        }
    }

    private void loadCommands(){
        commandsMap.put("AAAA",new AAAACommand());
        commandsMap.put("A",new ACommand());
        commandsMap.put("ALL",new AllCommand());
        commandsMap.put("EXISTS",new ExistsCommand());
        commandsMap.put("INCLUDE",new IncludesCommand());
        commandsMap.put("IP4",new Ip4Command());
        commandsMap.put("IP6",new Ip6Command());
        commandsMap.put("MX",new MxCommand());
        commandsMap.put("PTR",new PtrCommand());

    }

}
