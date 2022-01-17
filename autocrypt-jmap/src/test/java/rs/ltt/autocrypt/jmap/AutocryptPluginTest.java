package rs.ltt.autocrypt.jmap;

import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteStreams;
import com.google.common.net.MediaType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import rs.ltt.autocrypt.client.Decision;
import rs.ltt.autocrypt.client.Recommendation;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.jmap.common.entity.*;
import rs.ltt.jmap.common.entity.query.EmailQuery;
import rs.ltt.jmap.mock.server.JmapDispatcher;
import rs.ltt.jmap.mock.server.MockMailServer;
import rs.ltt.jmap.mua.Mua;
import rs.ltt.jmap.mua.cache.InMemoryCache;

public class AutocryptPluginTest {

    @Test
    public void getAutocryptClientBeforeInstall() {
        final AutocryptPlugin autocryptPlugin =
                new AutocryptPlugin("test@example.com", new InMemoryStorage());
        Assertions.assertThrows(IllegalStateException.class, autocryptPlugin::getAutocryptClient);
    }

    @Test
    public void injectAndReadBack() throws ExecutionException, InterruptedException {
        final MockWebServer server = new MockWebServer();
        final MockMailServer mailServer = new MockMailServer(2);
        server.setDispatcher(mailServer);
        final String username = mailServer.getUsername();
        final EmailAddress self = EmailAddress.builder().email(username).build();

        final Storage storage = new InMemoryStorage();
        final AutocryptPlugin autocryptPlugin = new AutocryptPlugin(username, storage);
        try (final Mua mua =
                Mua.builder()
                        .sessionResource(server.url(JmapDispatcher.WELL_KNOWN_PATH))
                        .username(mailServer.getUsername())
                        .password(JmapDispatcher.PASSWORD)
                        .accountId(mailServer.getAccountId())
                        .plugin(AutocryptPlugin.class, autocryptPlugin)
                        .build()) {
            mua.query(EmailQuery.unfiltered(true)).get();
            final Email email =
                    Email.builder()
                            .subject("This is a Test")
                            .from(self)
                            .to(EmailAddress.builder().email("bob@example.com").build())
                            .build();
            mua.draft(email).get();
            mua.refresh().get();
            final AutocryptClient autocryptClient =
                    mua.getPlugin(AutocryptPlugin.class).getAutocryptClient();
            final Decision decision =
                    Recommendation.combine(
                            autocryptClient
                                    .getRecommendationsForAddresses(
                                            Collections.singleton(self), false)
                                    .get());
            Assertions.assertEquals(Decision.AVAILABLE, decision);

            final Email wrapper = Email.builder().to(self).build();
            final Decision decisionDerivedByWrapper =
                    Recommendation.combine(autocryptClient.getRecommendations(wrapper, true).get());
            Assertions.assertEquals(Decision.ENCRYPT, decisionDerivedByWrapper);

            final Email wrapperBcc = Email.builder().bcc(self).build();
            final Decision decisionDerivedByWrapperBcc =
                    Recommendation.combine(
                            autocryptClient.getRecommendations(wrapperBcc, false).get());
            Assertions.assertEquals(Decision.DISABLE, decisionDerivedByWrapperBcc);
        }
    }

    @Test
    public void encryptAndUpload()
            throws ExecutionException, InterruptedException, TimeoutException {
        final FixedKeyStorage storage =
                new FixedKeyStorage(
                        FixedKeyStorage.SECRET_KEY_ALICE,
                        Collections.singleton(
                                PGPainless.extractCertificate(FixedKeyStorage.SECRET_KEY_BOB)));

        final MockWebServer server = new MockWebServer();
        final MockMailServer mailServer = new MockMailServer(2);
        server.setDispatcher(mailServer);

        final Mua mua =
                Mua.builder()
                        .cache(new InMemoryCache())
                        .sessionResource(server.url(JmapDispatcher.WELL_KNOWN_PATH))
                        .username(mailServer.getUsername())
                        .password(JmapDispatcher.PASSWORD)
                        .accountId(mailServer.getAccountId())
                        .plugin(
                                AutocryptPlugin.class,
                                new AutocryptPlugin(mailServer.getUsername(), storage))
                        .build();

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

        final Upload upload =
                mua.getPlugin(AutocryptPlugin.class)
                        .encryptAndUpload(recipients, bodyParts, null)
                        .get(30, TimeUnit.SECONDS);

        Assertions.assertTrue(upload.getSize() > 1000);
    }

    @Test
    public void downloadAndDecrypt() throws ExecutionException, InterruptedException {
        final FixedKeyStorage storage =
                new FixedKeyStorage(
                        FixedKeyStorage.SECRET_KEY_ALICE,
                        Collections.singleton(
                                PGPainless.extractCertificate(FixedKeyStorage.SECRET_KEY_BOB)));

        final MockWebServer server = new MockWebServer();
        final MockMailServer mailServer = new MockMailServer(2);
        server.setDispatcher(mailServer);

        final Mua mua =
                Mua.builder()
                        .cache(new InMemoryCache())
                        .sessionResource(server.url(JmapDispatcher.WELL_KNOWN_PATH))
                        .username(mailServer.getUsername())
                        .password(JmapDispatcher.PASSWORD)
                        .accountId(mailServer.getAccountId())
                        .plugin(
                                AutocryptPlugin.class,
                                new AutocryptPlugin(mailServer.getUsername(), storage))
                        .build();
        final Downloadable downloadable =
                EncryptedBodyPart.getDownloadable("a85f2332-afc9-4a3a-b38f-45eecd81004a");
        final List<byte[]> attachments = new ArrayList<>();
        final Email originalEmail = Email.builder().receivedAt(Instant.now()).build();
        final Email email =
                mua.getPlugin(AutocryptPlugin.class)
                        .downloadAndDecrypt(
                                downloadable,
                                (attachment, inputStream) -> {
                                    final ByteArrayOutputStream attachmentOutputStream =
                                            new ByteArrayOutputStream();
                                    final long bytes =
                                            ByteStreams.copy(inputStream, attachmentOutputStream);
                                    attachments.add(attachmentOutputStream.toByteArray());
                                    return bytes;
                                },
                                originalEmail)
                        .get();
        Assertions.assertEquals(1, attachments.size());
        Assertions.assertEquals(1, email.getAttachments().size());
        Assertions.assertEquals(1, email.getTextBody().size());
        System.out.println(email);
    }
}
