package rs.ltt.autocrypt.client.storage;

import org.immutables.value.Value;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

@Value.Immutable
public interface AccountState {

    boolean isEnabled();

    byte[] getSecretKey();

    EncryptionPreference getEncryptionPreference();
}
