package spf_resolver.spf_custom_exceptions;

public class SpfDnsException extends RuntimeException {
    public SpfDnsException(String message) {
        super(message);
    }
    public SpfDnsException(String message, Throwable t) {
        super(message,t);
    }
}
