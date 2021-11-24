package rs.ltt.autocrypt.client;

import java.time.Instant;

public abstract class AbstractAutocryptUpdate {

    private final String from;
    private final Instant effectiveDate;
    private final byte[] keyData;

    public AbstractAutocryptUpdate(
            final String from, final Instant effectiveDate, final byte[] keyData) {
        this.from = from;
        this.effectiveDate = effectiveDate;
        this.keyData = keyData;
    }

    public String getFrom() {
        return from;
    }

    public Instant getEffectiveDate() {
        return effectiveDate;
    }

    public byte[] getKeyData() {
        return keyData;
    }
}
