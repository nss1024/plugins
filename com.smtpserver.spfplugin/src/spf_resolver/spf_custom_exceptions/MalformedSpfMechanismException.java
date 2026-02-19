package spf_resolver.spf_custom_exceptions;

public class MalformedSpfMechanismException extends SpfParseException {
    public MalformedSpfMechanismException(String message) {
        super(message);
    }

    public MalformedSpfMechanismException(String message, Throwable t) {
        super(message,t);
    }
}
