package rs.ltt.autocrypt.client;

import java.time.Instant;
import java.util.Collections;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.PeerState;
import rs.ltt.autocrypt.client.storage.Storage;

public class PeerStateManagerTest {

    @Test
    public void processHeader() {
        final Storage storage = new InMemoryStorage();
        final PeerStateManager peerStateManager = new PeerStateManager(storage);

        final Instant effectiveDate = Instant.now();

        peerStateManager.processAutocryptHeaders(
                "test@example.com",
                effectiveDate,
                Collections.singleton("addr=test@example.com; keydata=AAo="));
        final PeerState peerState = storage.getPeerState("test@example.com");
        Assertions.assertNotNull(peerState);

        Assertions.assertEquals(effectiveDate, peerState.getLastSeen());
        Assertions.assertEquals(effectiveDate, peerState.getAutocryptTimestamp());
        Assertions.assertEquals(
                EncryptionPreference.NO_PREFERENCE, peerState.getEncryptionPreference());
    }
}
