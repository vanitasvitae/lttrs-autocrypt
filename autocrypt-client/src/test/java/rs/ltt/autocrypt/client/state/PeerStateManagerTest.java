package rs.ltt.autocrypt.client.state;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.Decision;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.PeerState;
import rs.ltt.autocrypt.client.storage.Storage;

public class PeerStateManagerTest {

    private static final Instant EFFECTIVE_DATE_INITIAL = Instant.ofEpochSecond(1_500_000_000);
    private static final Instant EFFECTIVE_DATE_UPDATE = Instant.ofEpochSecond(1_600_000_000);
    private static final Instant EFFECTIVE_DATE_EARLIER_UPDATE =
            Instant.ofEpochSecond(1_550_000_000);

    private static final String EXAMPLE_HEADER =
            "addr=test@example.com; prefer-encrypt=nopreference; keydata=mDMEYayg9BYJKwYBBAHa\n"
                + "Rw8BAQdAXNE+WhE4MzTK8UYL9BPvXa4vvpTi91kyePuDsp3Zl660HFRlc3QgVGVzdCA8dGVzdEBleGFt\n"
                + "cGxlLmNvbT6IjwQTFgoAQQUCYayg9AmQ2bYzbbMLwX0WoQT9xNDMu1y5/5bSfW3ZtjNtswvBfQKeAQKb\n"
                + "AQWWAgMBAASLCQgHBZUKCQgLApkBAAClTQD7BlPx15g89a4xYaNnFKUfTAxKXjA5B9KO6stEwi2HDYgB\n"
                + "ANkakdV/VcdOMyklo75z6wGa3AlAvA9n+8fnj6/UkrUGuDgEYayg9BIKKwYBBAGXVQEFAQEHQPv1w6k2\n"
                + "ShWEvw1UCyrgCQbuzGQQzLSgquNGzb9qezwDAwEIB4h1BBgWCgAdBQJhrKD0Ap4BApsMBZYCAwEABIsJ\n"
                + "CAcFlQoJCAsACgkQ2bYzbbMLwX3jEgEAm02M1HktY8aGvNpKmSWXoTWOWRGIZxMA1NhAFS7ce9wA/2Ju\n"
                + "6EiQsDXARz6+yQRW3nhyTRcdNf27G+93SpLBd44HuDMEYayg9BYJKwYBBAHaRw8BAQdA6UJC37S+8myZ\n"
                + "kvwxFYDAFqCGJN6XE61d70i5GPiZTyuI1QQYFgoAfQUCYayg9AKeAQKbAgWWAgMBAASLCQgHBZUKCQgL\n"
                + "XyAEGRYKAAYFAmGsoPQACgkQEEFKC1yIxmuFRAD+OHKaq12Jj+OJokJiF8CDIe1NrpwdpOTYyN47+V3U\n"
                + "+5QBAMl07HdfYIXR5r5SaEQOgqLqtu5JnXL5xGv26DcGOXkNAAoJENm2M22zC8F9IiEA/RlT+sIaGbwq\n"
                + "KsAFDSqpRX5VR1/QzyfafS9qWfL93qyMAQCDwKyemcwRo2m7/dJ8b+oHQAFnhmp/nZyXeBB1xdCACA==";

    @Test
    public void processHeader() {
        final Storage storage = new InMemoryStorage();
        final PeerStateManager peerStateManager = new PeerStateManager(storage);

        peerStateManager.processAutocryptHeaders(
                "test@example.com", EFFECTIVE_DATE_INITIAL, Collections.singleton(EXAMPLE_HEADER));
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
                "test@example.com", EFFECTIVE_DATE_INITIAL, Collections.singleton(EXAMPLE_HEADER));

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

    @Test
    public void preliminaryRecommendationAvailable() {
        final PeerStateManager peerStateManager = new PeerStateManager(new InMemoryStorage());

        peerStateManager.processAutocryptHeaders(
                "test@example.com", EFFECTIVE_DATE_INITIAL, Collections.singleton(EXAMPLE_HEADER));

        Assertions.assertEquals(
                Decision.AVAILABLE,
                peerStateManager.getPreliminaryRecommendation("test@example.com").getDecision());
    }

    @Test
    public void preliminaryRecommendationDiscourage() {
        final PeerStateManager peerStateManager = new PeerStateManager(new InMemoryStorage());

        peerStateManager.processAutocryptHeaders(
                "test@example.com", EFFECTIVE_DATE_INITIAL, Collections.singleton(EXAMPLE_HEADER));

        peerStateManager.processAutocryptHeaders(
                "test@example.com",
                EFFECTIVE_DATE_UPDATE.plus(Duration.ofDays(90)),
                Collections.emptyList());

        Assertions.assertEquals(
                Decision.DISCOURAGE,
                peerStateManager.getPreliminaryRecommendation("test@example.com").getDecision());
    }

    @Test
    public void preliminaryRecommendationDisabled() {
        final PeerStateManager peerStateManager = new PeerStateManager(new InMemoryStorage());

        Assertions.assertEquals(
                Decision.DISABLE,
                peerStateManager.getPreliminaryRecommendation("nobody@example.com").getDecision());
    }
}
