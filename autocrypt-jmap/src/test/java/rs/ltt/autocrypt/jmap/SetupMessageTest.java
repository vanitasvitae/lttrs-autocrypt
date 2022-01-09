package rs.ltt.autocrypt.jmap;

import com.google.common.base.CharMatcher;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.PassphraseHint;
import rs.ltt.jmap.mock.server.JmapDispatcher;
import rs.ltt.jmap.mock.server.MockMailServer;
import rs.ltt.jmap.mua.Mua;
import rs.ltt.jmap.mua.cache.InMemoryCache;

public class SetupMessageTest {

    @Test
    public void generatePassphrase() {
        for (int i = 0; i < 1000; ++i) {
            final String passphrase = SetupMessage.generateSetupCode();
            Assertions.assertEquals(36, passphrase.length());
            Assertions.assertTrue(CharMatcher.inRange('0', '9').matchesAllOf(passphrase));
        }
    }

    @Test
    public void storeAndDiscover() throws ExecutionException, InterruptedException {
        final FixedKeyStorage storage =
                new FixedKeyStorage(FixedKeyStorage.SECRET_KEY_ALICE, Collections.emptyList());

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
        mua.refresh().get();
        final String passphrase = SetupMessage.generateSetupCode();
        mua.getPlugin(AutocryptPlugin.class).storeSetupMessage(passphrase).get();
        final String setupMessage =
                mua.getPlugin(AutocryptPlugin.class).discoverSetupMessage().get().get();
        final PassphraseHint passphraseHint = PassphraseHint.of(setupMessage);
        Assertions.assertEquals(PassphraseHint.Format.NUMERIC9X4, passphraseHint.format);
        Assertions.assertEquals(passphrase.substring(0, 2), passphraseHint.begin);
    }
}
