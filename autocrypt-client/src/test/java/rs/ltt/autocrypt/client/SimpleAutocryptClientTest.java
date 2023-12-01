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
import rs.ltt.autocrypt.client.storage.*;

public class SimpleAutocryptClientTest {

    @Test
    public void nullExecutor() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () ->
                        SimpleAutocryptClient.builder()
                                .userId("foo@example.com")
                                .ioExecutorService(null)
                                .build());
    }

    @Test
    public void nullStorage() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () ->
                        SimpleAutocryptClient.builder()
                                .userId("foo@example.com")
                                .storage(null)
                                .build());
    }

    @Test
    public void nullDefaultSettings() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () ->
                        SimpleAutocryptClient.builder()
                                .userId("foo@example.com")
                                .defaultSettings(null)
                                .build());
    }

    @Test
    public void automaticSecretKeyGeneration() throws ExecutionException, InterruptedException {
        final SimpleAutocryptClient autocryptClient =
                SimpleAutocryptClient.builder().userId("test@example.com").build();
        final AutocryptHeader autocryptHeader = autocryptClient.getAutocryptHeader().get();

        PGPPublicKeyRing publicKey = PGPKeyRings.readPublicKeyRing(autocryptHeader.getKeyData());
        Assertions.assertEquals("test@example.com", autocryptHeader.getAddress());
        Assertions.assertTrue(PGPKeyRings.isSuitableForEncryption(publicKey));

        Assertions.assertNull(autocryptClient.ensureEverythingIsSetup().get());
    }

    @Test
    public void brokenStorageBackend() {
        final Storage brokenStorage =
                new Storage() {
                    @Override
                    public boolean updateLastSeen(String address, Instant effectiveDate) {
                        return false;
                    }

                    @Override
                    public void updateAutocrypt(
                            String address,
                            Instant effectiveDate,
                            byte[] publicKey,
                            EncryptionPreference preference) {}

                    @Override
                    public boolean updateGossip(
                            String address, Instant effectiveData, byte[] publicKey) {
                        return false;
                    }

                    @Override
                    public PeerState getPeerState(String address) {
                        return null;
                    }

                    @Override
                    public AccountState getAccountState(String userId) {
                        return ImmutableAccountState.builder()
                                .secretKey(new byte[] {})
                                .isEnabled(true)
                                .encryptionPreference(EncryptionPreference.NO_PREFERENCE)
                                .build();
                    }

                    @Override
                    public void setAccountState(String userId, AccountState accountState) {}
                };
        final SimpleAutocryptClient autocryptClient =
                SimpleAutocryptClient.builder()
                        .userId("test@example.com")
                        .storage(brokenStorage)
                        .build();
        final ExecutionException ee =
                Assertions.assertThrows(
                        ExecutionException.class,
                        () -> autocryptClient.ensureEverythingIsSetup().get());
        assertThat(ee.getCause(), CoreMatchers.instanceOf(IllegalStateException.class));
    }

    @Test
    public void aliceAndBobDefaultRecommendation() throws ExecutionException, InterruptedException {
        final SimpleAutocryptClient aliceClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        final SimpleAutocryptClient bobClient =
                SimpleAutocryptClient.builder().userId("bob@example.com").build();

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
    public void recommendationForDisabledAccount() throws ExecutionException, InterruptedException {
        final SimpleAutocryptClient aliceClient =
                SimpleAutocryptClient.builder()
                        .defaultSettings(
                                new DefaultSettings(false, EncryptionPreference.NO_PREFERENCE))
                        .userId("alice@example.com")
                        .build();
        final SimpleAutocryptClient bobClient =
                SimpleAutocryptClient.builder().userId("bob@example.com").build();

        aliceClient
                .processAutocryptHeader(
                        "bob@example.com",
                        Instant.now(),
                        bobClient.getAutocryptHeader().get().toHeaderValue())
                .get();
        final Recommendation recommendation =
                aliceClient.getRecommendation("bob@example.com", false).get();
        Assertions.assertEquals(Decision.DISABLE, recommendation.getDecision());

        final Decision decision =
                Recommendation.combine(
                        aliceClient
                                .getRecommendations(
                                        Arrays.asList("bob@example.com", "bob@example.com"))
                                .get());
        Assertions.assertEquals(Decision.DISABLE, decision);
    }

    @Test
    public void recommendationsMultipleReceiver() throws ExecutionException, InterruptedException {
        final SimpleAutocryptClient aliceClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        final SimpleAutocryptClient bobClient =
                SimpleAutocryptClient.builder().userId("bob@example.com").build();

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
        final SimpleAutocryptClient aliceClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        aliceClient.setEncryptionPreference(EncryptionPreference.MUTUAL).get();

        final SimpleAutocryptClient bobClient =
                SimpleAutocryptClient.builder().userId("bob@example.com").build();
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
        final SimpleAutocryptClient clientOne =
                SimpleAutocryptClient.builder()
                        .userId("alice@example.com")
                        .storage(storage)
                        .build();
        final String headerOne = clientOne.getAutocryptHeader().get().toHeaderValue();
        final String headerTwo = clientOne.getAutocryptHeader().get().toHeaderValue();

        Assertions.assertEquals(headerOne, headerTwo);

        final SimpleAutocryptClient clientTwo =
                SimpleAutocryptClient.builder()
                        .userId("alice@example.com")
                        .storage(storage)
                        .build();
        final String headerThree = clientTwo.getAutocryptHeader().get().toHeaderValue();

        Assertions.assertEquals(headerTwo, headerThree);
    }

    @Test
    public void encryptToBob() throws IOException, ExecutionException, InterruptedException {
        final SimpleAutocryptClient aliceClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        final SimpleAutocryptClient bobClient =
                SimpleAutocryptClient.builder().userId("bob@example.com").build();

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
                        .encrypt(Collections.singleton("bob@example.com"), byteArrayOutputStream)
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
            Assertions.assertEquals(-1, decryptionStream.read());
        }

        Assertions.assertEquals("Hello World!", resultStream.toString());
    }

    @Test
    public void encryptToUnknown() {
        final SimpleAutocryptClient aliceClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final ExecutionException exception =
                Assertions.assertThrows(
                        ExecutionException.class,
                        () ->
                                aliceClient
                                        .encrypt(
                                                Collections.singleton("unknown@example.com"),
                                                byteArrayOutputStream)
                                        .get());
        assertThat(exception.getCause(), CoreMatchers.instanceOf(IllegalArgumentException.class));
    }
}
