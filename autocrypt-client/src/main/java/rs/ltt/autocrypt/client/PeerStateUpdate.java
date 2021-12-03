package rs.ltt.autocrypt.client;

import com.google.common.base.Preconditions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class PeerStateUpdate extends AbstractAutocryptUpdate {

    private final EncryptionPreference encryptionPreference;

    private PeerStateUpdate(
            final String from,
            final Instant effectiveDate,
            final EncryptionPreference encryptionPreference,
            final byte[] keyData) {
        super(from, effectiveDate, keyData);
        this.encryptionPreference = encryptionPreference;
    }

    public static Builder builder(final String from, final Instant effectiveDate) {
        return new Builder(from, effectiveDate);
    }

    public EncryptionPreference getEncryptionPreference() {
        return encryptionPreference == null
                ? EncryptionPreference.NO_PREFERENCE
                : encryptionPreference;
    }

    public static class Builder {
        private final String from;
        private final Instant effectiveDate;
        private final List<AutocryptHeader> headers = new ArrayList<>();

        private Builder(final String from, final Instant effectiveDate) {
            Preconditions.checkNotNull(from);
            Preconditions.checkNotNull(effectiveDate);
            this.from = from;
            this.effectiveDate = effectiveDate;
        }

        public Builder addAll(final Collection<String> headers) {
            for (final String header : headers) {
                add(header);
            }
            return this;
        }

        public Builder add(final String header) {
            final AutocryptHeader autocryptHeader;
            try {
                autocryptHeader = AutocryptHeader.parse(header);
            } catch (final Exception e) {
                // improperly formatted headers will just be ignored
                return this;
            }
            return add(autocryptHeader);
        }

        public Builder add(final AutocryptHeader header) {
            Preconditions.checkNotNull(header);
            if (this.from.equals(header.getAddress())) {
                this.headers.add(header);
            }
            return this;
        }

        public PeerStateUpdate build() {
            if (headers.isEmpty()) {
                throw new IllegalStateException(
                        "Cannot build PeerStateUpdate, no valid headers have been processed");
            }
            if (headers.size() > 1) {
                throw new IllegalStateException(
                        String.format(
                                "Cannot build PeerStateUpdate, %d valid headers have been found",
                                headers.size()));
            }
            final AutocryptHeader autocryptHeader = headers.get(0);
            return new PeerStateUpdate(
                    from,
                    effectiveDate,
                    autocryptHeader.getEncryptionPreference(),
                    autocryptHeader.getKeyData());
        }
    }
}
