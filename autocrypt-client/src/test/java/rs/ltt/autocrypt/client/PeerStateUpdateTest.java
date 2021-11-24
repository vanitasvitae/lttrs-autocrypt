package rs.ltt.autocrypt.client;

import java.time.Instant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PeerStateUpdateTest {

    @Test
    public void noHeaders() {
        final PeerStateUpdate.Builder builder =
                PeerStateUpdate.builder("test@example.com", Instant.now());
        Assertions.assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    public void oneValidHeader() {
        final PeerStateUpdate.Builder builder =
                PeerStateUpdate.builder("test@example.com", Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.build();
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
        final PeerStateUpdate.Builder builder =
                PeerStateUpdate.builder("test@example.com", Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.add("addr=test@example.com; keydata=AAo=; invalid=attribute");
        builder.build();
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
