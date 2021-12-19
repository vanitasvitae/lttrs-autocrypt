package rs.ltt.autocrypt.jmap;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.io.CharSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.apache.james.mime4j.Charsets;
import org.apache.james.mime4j.dom.BinaryBody;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.dom.MessageWriter;
import org.apache.james.mime4j.message.BodyPartBuilder;
import org.apache.james.mime4j.message.DefaultMessageWriter;
import org.apache.james.mime4j.message.MultipartBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;

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
                AutocryptClient.builder().userId("alice@example.com").build();
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
        assertThat(headerValue, containsString("prefer-encrypt=nopreference"));
    }

    @Test
    public void encryptMimeMessage() throws IOException {
        InputStream targetStream =
                CharSource.wrap("Hello World").asByteSource(StandardCharsets.UTF_8).openStream();
        final Message message =
                Message.Builder.of()
                        .setBody(
                                MultipartBuilder.create("mixed")
                                        .addBodyPart(
                                                BodyPartBuilder.create()
                                                        .setBody("Täst", Charsets.UTF_8)
                                                        .setContentTransferEncoding(
                                                                "quoted-printable"))
                                        .addBodyPart(
                                                BodyPartBuilder.create()
                                                        .setBody(
                                                                new BinaryBody() {
                                                                    @Override
                                                                    public InputStream
                                                                            getInputStream()
                                                                                    throws
                                                                                            IOException {
                                                                        System.out.println(
                                                                                "Reading"
                                                                                    + " inputstream");
                                                                        return targetStream;
                                                                    }
                                                                })
                                                        .setContentDisposition(
                                                                "attachment", "hello.png")
                                                        .setContentType("image/png")
                                                        .setContentTransferEncoding("base64"))
                                        .build())
                        .build();
        System.out.println("email built!");
        MessageWriter messageWriter = new DefaultMessageWriter();
        messageWriter.writeMessage(message, System.out);
    }
}
