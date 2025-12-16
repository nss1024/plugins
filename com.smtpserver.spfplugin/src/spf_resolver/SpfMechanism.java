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

    public SpfQualifier getQualifier() {
        return qualifier;
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

    @Override
    public String toString() {
        return "SpfMechanism{" +
                "qualifier=" + qualifier +
                ", type=" + type +
                ", domain='" + domain + '\'' +
                ", prefix=" + prefix +
                '}';
    }
}
