package rs.ltt.autocrypt.client;

import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class DefaultSettings {

    public static final DefaultSettings DEFAULT =
            new DefaultSettings(true, EncryptionPreference.NO_PREFERENCE);

    private final boolean enabled;
    private final EncryptionPreference encryptionPreference;

    public DefaultSettings(boolean enabled, EncryptionPreference encryptionPreference) {
        this.enabled = enabled;
        this.encryptionPreference = encryptionPreference;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public EncryptionPreference getEncryptionPreference() {
        return encryptionPreference;
    }
}
