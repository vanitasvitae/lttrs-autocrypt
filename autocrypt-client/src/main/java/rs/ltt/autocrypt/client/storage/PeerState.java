package rs.ltt.autocrypt.client.storage;

import java.time.Instant;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public interface PeerState {

    Instant getLastSeen();

    Instant getAutocryptTimestamp();

    Instant getGossipTimestamp();

    byte[] getPublicKey();

    byte[] getGossipKey();

    EncryptionPreference getEncryptionPreference();
}
