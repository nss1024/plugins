package spf_resolver;

public class SpfMechanism {

    public enum Qualifier {
        PASS('+'),
        FAIL('-'),
        SOFTFAIL('~'),
        NEUTRAL('?');

        private final char symbol;

        Qualifier(char symbol) {
            this.symbol = symbol;
        }

        public char getSymbol() {
            return symbol;
        }

        public static Qualifier fromChar(char c) {
            for (Qualifier q : values()) {
                if (q.symbol == c) return q;
            }
            throw new IllegalArgumentException("Invalid SPF qualifier: " + c);
        }
    }

    public enum Type { A, MX, INCLUDE, IP4, IP6, ALL, EXISTS, PTR }

    private Qualifier qualifier;
    private Type type;
    private String domain;
    private Integer prefix;

    public SpfMechanism(Qualifier qualifier, Type type, String domain, Integer prefix) {
        this.qualifier = qualifier;
        this.type = type;
        this.domain = domain;
        this.prefix = prefix;
    }

    public char getQualifier() {
        return qualifier.getSymbol();
    }

    public Type getType() {
        return type;
    }

    public String getDomain() {
        return domain;
    }

    public Integer getPrefix() {
        return prefix;
    }
}
