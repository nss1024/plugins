package spf_resolver.spf_custom_exceptions;

public class SpfParseException extends RuntimeException {
    public SpfParseException(String message) {
        super(message);
    }
    public SpfParseException(String message, Throwable cause) { super(message, cause); }

}
