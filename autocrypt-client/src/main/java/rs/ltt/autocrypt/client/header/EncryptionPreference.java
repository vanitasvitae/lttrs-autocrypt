package rs.ltt.autocrypt.client.header;

import com.google.common.base.CharMatcher;
import java.util.Locale;

public enum EncryptionPreference {
    MUTUAL,
    NO_PREFERENCE;

    public static EncryptionPreference of(final String value) {
        for (EncryptionPreference ep : values()) {
            if (ep.toString().equals(value)) {
                return ep;
            }
        }
        throw new IllegalArgumentException(
                String.format("%s is not a known encryption preference", value));
    }

    @Override
    public String toString() {
        return CharMatcher.inRange('a', 'z').retainFrom(super.toString().toLowerCase(Locale.ROOT));
    }
}
