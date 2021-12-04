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

    private static final Instant EFFECTIVE_DATE_INITIAL = Instant.ofEpochSecond(1_500_000_000);
    private static final Instant EFFECTIVE_DATE_UPDATE = Instant.ofEpochSecond(1_600_000_000);
    private static final Instant EFFECTIVE_DATE_EARLIER_UPDATE =
            Instant.ofEpochSecond(1_550_000_000);

    @Test
    public void processHeader() {
        final Storage storage = new InMemoryStorage();
        final PeerStateManager peerStateManager = new PeerStateManager(storage);

        peerStateManager.processAutocryptHeaders(
                "test@example.com",
                EFFECTIVE_DATE_INITIAL,
                Collections.singleton("addr=test@example.com; keydata=AAo="));
        final PeerState peerState = storage.getPeerState("test@example.com");
        Assertions.assertNotNull(peerState);

        Assertions.assertEquals(EFFECTIVE_DATE_INITIAL, peerState.getLastSeen());
        Assertions.assertEquals(EFFECTIVE_DATE_INITIAL, peerState.getAutocryptTimestamp());
        Assertions.assertEquals(
                EncryptionPreference.NO_PREFERENCE, peerState.getEncryptionPreference());
    }

    @Test
    public void processEmptyHeader() {
        final Storage storage = new InMemoryStorage();
        final PeerStateManager peerStateManager = new PeerStateManager(storage);

        peerStateManager.processAutocryptHeaders(
                "test@example.com", EFFECTIVE_DATE_INITIAL, Collections.emptyList());
        final PeerState peerState = storage.getPeerState("test@example.com");
        Assertions.assertNotNull(peerState);

        Assertions.assertEquals(EFFECTIVE_DATE_INITIAL, peerState.getLastSeen());
        Assertions.assertNull(peerState.getPublicKey());
    }

    @Test
    public void processHeaderAndUpdate() {
        final Storage storage = new InMemoryStorage();
        final PeerStateManager peerStateManager = new PeerStateManager(storage);

        peerStateManager.processAutocryptHeaders(
                "test@example.com",
                EFFECTIVE_DATE_INITIAL,
                Collections.singleton("addr=test@example.com; keydata=AAo="));

        peerStateManager.processAutocryptHeaders(
                "test@example.com", EFFECTIVE_DATE_UPDATE, Collections.emptyList());

        peerStateManager.processAutocryptHeaders(
                "test@example.com", EFFECTIVE_DATE_EARLIER_UPDATE, Collections.emptyList());

        final PeerState peerState = storage.getPeerState("test@example.com");
        Assertions.assertNotNull(peerState);

        Assertions.assertEquals(EFFECTIVE_DATE_UPDATE, peerState.getLastSeen());
        Assertions.assertEquals(EFFECTIVE_DATE_INITIAL, peerState.getAutocryptTimestamp());

        Assertions.assertNotNull(peerState.getPublicKey());
    }
}
