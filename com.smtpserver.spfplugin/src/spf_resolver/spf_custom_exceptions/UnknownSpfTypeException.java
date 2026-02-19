package spf_resolver.spf_custom_exceptions;

public class UnknownSpfTypeException extends SpfParseException{
    public UnknownSpfTypeException(String e){
        super(e);
    }

}
