package rs.ltt.autocrypt.client.state;

import java.time.Instant;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
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

    @Test
    public void exampleHeader() {
        final String example =
                "addr=alice@autocrypt.example; prefer-encrypt=mutual; keydata=\n"
                    + " mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/Ub7O1u120F2F\n"
                    + " saWNlQGF1dG9jcnlwdC5leGFtcGxliJYEExYIAD4WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXE\n"
                    + " cE6QIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDyMVUMT0fjjkqLAP9frlijw\n"
                    + " BJvA+HFnqCZcYIVxlyXzS5Gi5gMTpp37K73jgD/VbKYhkwk9iu689OYH4K7q7LbmdeaJ+RX88Y/\n"
                    + " ad9hZwy4OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3sE9+\n"
                    + " eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIbDAAKCRDyMVUMT0\n"
                    + " fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn0QEA22Kr7VkCjeAEC08VSTeV+\n"
                    + " QFsmz55/lntWkwYWhmvOgE=";
        final PeerStateUpdate peerStateUpdate =
                PeerStateUpdate.builder("alice@autocrypt.example", Instant.now())
                        .add(example)
                        .build();
        final PGPPublicKeyRing publicKeyRing = peerStateUpdate.getPublicKeyRing();
        final KeyRingInfo keyRingInfo = PGPainless.inspectKeyRing(publicKeyRing);
        Assertions.assertEquals("alice@autocrypt.example", keyRingInfo.getPrimaryUserId());
    }

    @Test
    public void normalizationCapitalizedFrom() {
        final PeerStateUpdate peerStateUpdate =
                PeerStateUpdate.builder("Test@example.com", Instant.now())
                        .add("addr=test@example.com; keydata=AAo=")
                        .build();
        Assertions.assertEquals("test@example.com", peerStateUpdate.getFrom());
        Assertions.assertEquals(
                EncryptionPreference.NO_PREFERENCE, peerStateUpdate.getEncryptionPreference());
    }

    @Test
    public void normalizationCapitalizedAddr() {
        final PeerStateUpdate peerStateUpdate =
                PeerStateUpdate.builder("test@example.com", Instant.now())
                        .add("addr=Test@example.com; keydata=AAo=")
                        .build();
        Assertions.assertEquals("test@example.com", peerStateUpdate.getFrom());
        Assertions.assertEquals(
                EncryptionPreference.NO_PREFERENCE, peerStateUpdate.getEncryptionPreference());
    }
}
