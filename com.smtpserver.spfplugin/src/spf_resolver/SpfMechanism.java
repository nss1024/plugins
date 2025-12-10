package spf_resolver;

public class SpfMechanism {

    private SpfQualifier qualifier;
    private SpfType type;
    private String domain;
    private Integer prefix;

    public SpfMechanism(SpfQualifier qualifier, SpfType type, String domain, Integer prefix) {
        this.qualifier = qualifier;
        this.type = type;
        this.domain = domain;
        this.prefix = prefix;
    }

    public char getQualifier() {
        return qualifier.getSymbol();
    }

    public SpfType getType() {
        return type;
    }

    public String getDomain() {
        return domain;
    }

    public Integer getPrefix() {
        return prefix;
    }
}
