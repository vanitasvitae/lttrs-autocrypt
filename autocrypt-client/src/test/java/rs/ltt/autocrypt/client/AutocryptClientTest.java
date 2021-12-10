package rs.ltt.autocrypt.client;

import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.io.ByteStreams;
import com.google.common.io.CharSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionStream;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;

public class AutocryptClientTest {

    @Test
    public void automaticSecretKeyGeneration() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient = new AutocryptClient("test@example.com");
        final AutocryptHeader autocryptHeader = autocryptClient.getAutocryptHeader().get();

        PGPPublicKeyRing publicKey = PGPKeyRings.readPublicKeyRing(autocryptHeader.getKeyData());
        Assertions.assertEquals("test@example.com", autocryptHeader.getAddress());
        Assertions.assertTrue(PGPKeyRings.isSuitableForEncryption(publicKey));
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

    @Test
    public void encryptToBob() throws IOException, ExecutionException, InterruptedException {
        final AutocryptClient aliceClient = new AutocryptClient("alice@example.com");
        final AutocryptClient bobClient = new AutocryptClient("bob@example.com");

        aliceClient
                .processAutocryptHeader(
                        "bob@example.com",
                        Instant.now(),
                        bobClient.getAutocryptHeader().get().toHeaderValue())
                .get();

        final InputStream inputStream =
                CharSource.wrap("Hello World!").asByteSource(StandardCharsets.UTF_8).openStream();

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try (final EncryptionStream encryptionStream =
                aliceClient
                        .encrypt(byteArrayOutputStream, Collections.singleton("bob@example.com"))
                        .get()) {
            ByteStreams.copy(inputStream, encryptionStream);
        }

        final String encryptedMessage = byteArrayOutputStream.toString();

        final InputStream encryptedInputStream =
                CharSource.wrap(encryptedMessage).asByteSource(StandardCharsets.UTF_8).openStream();

        final ByteArrayOutputStream resultStream = new ByteArrayOutputStream();

        try (final DecryptionStream decryptionStream =
                bobClient.decrypt(encryptedInputStream).get()) {
            ByteStreams.copy(decryptionStream, resultStream);
        }

        Assertions.assertEquals("Hello World!", resultStream.toString());
    }

    @Test
    public void encryptToUnknown() {
        final AutocryptClient aliceClient = new AutocryptClient("alice@example.com");
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final ExecutionException exception =
                Assertions.assertThrows(
                        ExecutionException.class,
                        () ->
                                aliceClient
                                        .encrypt(
                                                byteArrayOutputStream,
                                                Collections.singleton("unknown@example.com"))
                                        .get());
        assertThat(exception.getCause(), CoreMatchers.instanceOf(IllegalArgumentException.class));
    }
}
