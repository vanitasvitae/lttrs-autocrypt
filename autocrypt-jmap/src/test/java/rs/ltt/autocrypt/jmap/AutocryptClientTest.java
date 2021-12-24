package rs.ltt.autocrypt.jmap;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionResult;
import rs.ltt.autocrypt.client.DefaultSettings;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;
import rs.ltt.jmap.common.entity.EmailBodyPart;

public class AutocryptClientTest {

    @Test
    public void missingUserId() {
        Assertions.assertThrows(
                IllegalStateException.class, () -> AutocryptClient.builder().build());
    }

    @Test
    public void nullExecutor() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () ->
                        AutocryptClient.builder()
                                .userId("foo@example.com")
                                .ioExecutorService(null)
                                .build());
    }

    @Test
    public void nullStorage() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> AutocryptClient.builder().userId("foo@example.com").storage(null).build());
    }

    @Test
    public void nullDefaultSettings() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () ->
                        AutocryptClient.builder()
                                .userId("foo@example.com")
                                .defaultSettings(null)
                                .build());
    }

    @Test
    public void bbcRecipients() {
        final Email email =
                Email.builder()
                        .bcc(EmailAddress.builder().email("alice@example.com").build())
                        .build();
        Assertions.assertThrows(
                IllegalArgumentException.class, () -> AutocryptClient.recipients(email));
    }

    @Test
    public void invalidRecipients() {
        final Email email = Email.builder().to(EmailAddress.builder().build()).build();
        IllegalArgumentException iae =
                Assertions.assertThrows(
                        IllegalArgumentException.class, () -> AutocryptClient.recipients(email));
        Assertions.assertEquals("Some recipients do not have email addresses", iae.getMessage());
    }

    @Test
    public void noFromDraft() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder().userId("alice@example.com").build();
        final Email email =
                Email.builder()
                        .subject("This is a Test")
                        .to(EmailAddress.builder().email("bob@example.com").build())
                        .build();

        final Email processedEmail = autocryptClient.injectAutocryptHeader(email).get();

        final List<String> autocryptHeaders = processedEmail.getAutocrypt();
        Assertions.assertEquals(1, autocryptHeaders.size());
        final String headerValue = autocryptHeaders.get(0);
        assertThat(headerValue, startsWith("addr=alice@example.com;"));
    }

    @Test
    public void injectIntoEmail() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder()
                        .userId("alice@example.com")
                        .defaultSettings(new DefaultSettings(true, EncryptionPreference.MUTUAL))
                        .build();
        final Email email =
                Email.builder()
                        .subject("This is a Test")
                        .from(EmailAddress.builder().email("alice@example.com").build())
                        .to(EmailAddress.builder().email("bob@example.com").build())
                        .build();
        final Email result = autocryptClient.injectAutocryptHeader(email).get();
        final List<String> autocryptHeaders = result.getAutocrypt();
        Assertions.assertEquals(1, autocryptHeaders.size());
        final String headerValue = autocryptHeaders.get(0);
        assertThat(headerValue, startsWith("addr=alice@example.com;"));
        assertThat(headerValue, containsString("prefer-encrypt=mutual"));
    }

    @Test
    public void headerDifferentFrom() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder()
                        .userId("alice@example.com")
                        .defaultSettings(new DefaultSettings(true, EncryptionPreference.MUTUAL))
                        .build();
        final AutocryptHeader header =
                autocryptClient
                        .getAutocryptHeader(
                                EmailAddress.builder().email("support@example.com").build())
                        .get();
        Assertions.assertEquals(header.getAddress(), "support@example.com");
    }

    @Test
    public void disableAccountAndInject() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder()
                        .userId("bob@example.com")
                        .defaultSettings(new DefaultSettings(false, EncryptionPreference.MUTUAL))
                        .build();
        final Email email =
                Email.builder()
                        .subject("Normal subject")
                        .from(EmailAddress.builder().email("bob@example.com").build())
                        .to(EmailAddress.builder().email("alice@example.com").build())
                        .build();
        final Email result = autocryptClient.injectAutocryptHeader(email).get();
        final List<String> autocryptHeaders = result.getAutocrypt();
        Assertions.assertTrue(autocryptHeaders.isEmpty());
    }

    @Test
    public void encryptBodyParts() throws ExecutionException, InterruptedException {

        final FixedKeyStorage storage =
                new FixedKeyStorage(
                        FixedKeyStorage.SECRET_KEY_ALICE,
                        Collections.singleton(
                                PGPainless.extractCertificate(FixedKeyStorage.SECRET_KEY_BOB)));

        final AutocryptClient autocryptClient =
                AutocryptClient.builder().userId("alice@example.com").storage(storage).build();

        final ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
        final BodyPartTuple textBody =
                BodyPartTuple.of(
                        EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).build(),
                        "Hello World! Schöne Grüße");
        final BodyPartTuple attachment =
                BodyPartTuple.of(
                        EmailBodyPart.builder()
                                .mediaType(MediaType.PNG)
                                .name("blacksquare.png")
                                .disposition("attachment")
                                .build(),
                        new ByteArrayInputStream(MimeTransformerTest.BLACK_SQUARE_PNG));

        final List<EmailAddress> recipients =
                ImmutableList.of(EmailAddress.builder().email("bob@example.com").build());
        final List<BodyPartTuple> bodyParts = ImmutableList.of(textBody, attachment);

        final EncryptionResult result =
                autocryptClient.encrypt(recipients, bodyParts, resultOutputStream).get();

        Assertions.assertEquals(2, result.getRecipients().size());

        final String message = new String(resultOutputStream.toByteArray(), StandardCharsets.UTF_8);

        assertThat(message, startsWith("-----BEGIN PGP MESSAGE-----"));
        assertThat(message.trim(), endsWith("-----END PGP MESSAGE-----"));
    }
}
