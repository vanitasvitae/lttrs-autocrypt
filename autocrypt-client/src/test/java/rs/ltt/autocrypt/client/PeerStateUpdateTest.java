package rs.ltt.autocrypt.client;

import java.time.Instant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class PeerStateUpdateTest {

    @Test
    public void noHeaders() {
        final PeerStateUpdate.Builder builder =
                PeerStateUpdate.builder("test@example.com", Instant.now());
        Assertions.assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    public void oneValidHeader() {
        final PeerStateUpdate peerStateUpdate =
                PeerStateUpdate.builder("test@example.com", Instant.now())
                        .add("addr=test@example.com; keydata=AAo=")
                        .build();
        Assertions.assertEquals("test@example.com", peerStateUpdate.getFrom());
        Assertions.assertEquals(
                EncryptionPreference.NO_PREFERENCE, peerStateUpdate.getEncryptionPreference());
    }

    @Test
    public void twoValidHeader() {
        final PeerStateUpdate.Builder builder =
                PeerStateUpdate.builder("test@example.com", Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.add("addr=test@example.com; keydata=AAo=");
        final IllegalStateException exception =
                Assertions.assertThrows(IllegalStateException.class, builder::build);
        Assertions.assertEquals(
                "Cannot build PeerStateUpdate, 2 valid headers have been found",
                exception.getMessage());
    }

    @Test
    public void oneValidOneInvalidHeader() {
        Assertions.assertNotNull(
                PeerStateUpdate.builder("test@example.com", Instant.now())
                        .add("addr=test@example.com; keydata=AAo=")
                        .add("addr=test@example.com; keydata=AAo=; invalid=attribute")
                        .build());
    }

    @Test
    public void oneValidOneDifferentFromHeader() {
        final PeerStateUpdate.Builder builder =
                PeerStateUpdate.builder("test@example.com", Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.add("addr=other@example.com; keydata=AAo=");
        builder.build();
    }
}
