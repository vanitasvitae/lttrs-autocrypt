package rs.ltt.autocrypt.jmap;

import java.util.Collections;
import java.util.concurrent.ExecutionException;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.Decision;
import rs.ltt.autocrypt.client.Recommendation;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;
import rs.ltt.jmap.common.entity.query.EmailQuery;
import rs.ltt.jmap.mock.server.JmapDispatcher;
import rs.ltt.jmap.mock.server.MockMailServer;
import rs.ltt.jmap.mua.Mua;

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
        }
    }
}
