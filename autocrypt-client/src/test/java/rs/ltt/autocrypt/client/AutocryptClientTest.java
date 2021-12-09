package rs.ltt.autocrypt.client;

import java.time.Instant;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.AutocryptHeader;

public class AutocryptClientTest {

    @Test
    public void automaticSecretKeyGeneration() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient = new AutocryptClient("test@example.com");
        final AutocryptHeader autocryptHeader = autocryptClient.getAutocryptHeader().get();

        PGPPublicKeyRing publicKey =
                PGPPublicKeyRings.readPublicKeyRing(autocryptHeader.getKeyData());
        Assertions.assertEquals("test@example.com", autocryptHeader.getAddress());
        Assertions.assertTrue(PGPPublicKeyRings.isSuitableForEncryption(publicKey));
    }

    @Test
    public void aliceAndBobDefaultRecommendation() throws ExecutionException, InterruptedException {
        final AutocryptClient aliceClient = new AutocryptClient("alice@example.com");
        final AutocryptClient bobClient = new AutocryptClient("bob@example.com");

        aliceClient
                .processAutocryptHeader(
                        "bob@example.com",
                        Instant.now(),
                        bobClient.getAutocryptHeader().get().toHeaderValue())
                .get();
        final Recommendation recommendation =
                aliceClient.getRecommendation("bob@example.com", false).get();
        Assertions.assertEquals(Decision.AVAILABLE, recommendation.getDecision());

        final Recommendation recommendationReply =
                aliceClient.getRecommendation("bob@example.com", true).get();
        Assertions.assertEquals(Decision.ENCRYPT, recommendationReply.getDecision());

        final Recommendation recommendationNobody =
                aliceClient.getRecommendation("nobody@example.com", false).get();
        Assertions.assertEquals(Decision.DISABLE, recommendationNobody.getDecision());
    }
}
