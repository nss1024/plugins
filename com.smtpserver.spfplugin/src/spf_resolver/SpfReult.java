package spf_resolver;

public enum SpfReult {

    PASS, // Sender authorised.
    FAIL, // Sender not authorised -> fail
    SOFTFAIL, // Sender probably unauthorized -> mark as suspicious
    NEUTRAL, // The domain is not asserting whether this sender is permitted or not.
    NONE, // The domain has no SPF record. -> neutral
    TEMPERROR, //Temporary DNS issue. -> Try again later
    PERMERROR //The SPF record is invalid or cannot be processed. ->fail
}
