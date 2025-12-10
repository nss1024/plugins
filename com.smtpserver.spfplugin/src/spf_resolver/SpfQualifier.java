package spf_resolver;

public enum SpfQualifier {
    PASS('+'),
    FAIL('-'),
    SOFTFAIL('~'),
    NEUTRAL('?');

    private final char symbol;

    SpfQualifier(char symbol) {
        this.symbol = symbol;
    }

    public char getSymbol() {
        return symbol;
    }

}
