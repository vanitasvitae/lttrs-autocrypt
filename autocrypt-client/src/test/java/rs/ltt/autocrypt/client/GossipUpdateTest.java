package rs.ltt.autocrypt.client;

import java.time.Instant;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class GossipUpdateTest {

    @Test
    public void twoHeaderTwoResults() {
        final GossipUpdate.Builder builder = GossipUpdate.builder(Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.add("addr=alice@example.com; keydata=AAo=");
        Assertions.assertEquals(2, builder.build().size());
    }

    @Test
    public void threeHeaderOneResult() {
        final GossipUpdate.Builder builder = GossipUpdate.builder(Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.add("addr=test@example.com; keydata=AAo=");
        builder.add("addr=alice@example.com; keydata=AAo=");
        Assertions.assertEquals(1, builder.build().size());
    }

    @Test
    public void noValidHeaders() {
        final GossipUpdate.Builder builder = GossipUpdate.builder(Instant.now());
        builder.add("addr=test@example.com; keydata=AAo=; invalid=attribute");
        Assertions.assertEquals(0, builder.build().size());
    }
}
