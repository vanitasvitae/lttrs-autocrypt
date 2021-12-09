package rs.ltt.autocrypt.client;

import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;

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

    @Test
    public void recommendationsMultipleReceiver() throws ExecutionException, InterruptedException {
        final AutocryptClient aliceClient = new AutocryptClient("alice@example.com");
        final AutocryptClient bobClient = new AutocryptClient("bob@example.com");

        aliceClient
                .processAutocryptHeader(
                        "bob@example.com",
                        Instant.now(),
                        bobClient.getAutocryptHeader().get().toHeaderValue())
                .get();

        final Decision decision =
                Recommendation.combine(
                        aliceClient
                                .getRecommendations(
                                        Arrays.asList("bob@example.com", "nobobody@example.com"),
                                        false)
                                .get());
        Assertions.assertEquals(Decision.DISABLE, decision);
    }

    @Test
    public void aliceAndBobSetToMutual() throws ExecutionException, InterruptedException {
        final AutocryptClient aliceClient = new AutocryptClient("alice@example.com");
        aliceClient.setEncryptionPreference(EncryptionPreference.MUTUAL).get();
        final AutocryptClient bobClient = new AutocryptClient("bob@example.com");
        bobClient.setEncryptionPreference(EncryptionPreference.MUTUAL).get();

        aliceClient
                .processAutocryptHeader(
                        "bob@example.com",
                        Instant.now(),
                        bobClient.getAutocryptHeader().get().toHeaderValue())
                .get();

        final Recommendation recommendation =
                aliceClient.getRecommendation("bob@example.com", false).get();
        Assertions.assertEquals(Decision.ENCRYPT, recommendation.getDecision());
    }

    @Test
    public void publicKeyStaysTheSame() throws ExecutionException, InterruptedException {
        final Storage storage = new InMemoryStorage();
        final AutocryptClient clientOne = new AutocryptClient("test@example.com", storage);
        final String headerOne = clientOne.getAutocryptHeader().get().toHeaderValue();
        final String headerTwo = clientOne.getAutocryptHeader().get().toHeaderValue();

        Assertions.assertEquals(headerOne, headerTwo);

        final AutocryptClient clientTwo = new AutocryptClient("test@example.com", storage);
        final String headerThree = clientTwo.getAutocryptHeader().get().toHeaderValue();

        Assertions.assertEquals(headerTwo, headerThree);
    }
}
