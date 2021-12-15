package rs.ltt.autocrypt.jmap;

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import java.util.concurrent.ExecutionException;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.mua.plugin.EmailBuildStagePlugin;
import rs.ltt.jmap.mua.plugin.EmailCacheStagePlugin;
import rs.ltt.jmap.mua.service.PluginService;

public class AutocryptPlugin extends PluginService.Plugin
        implements EmailBuildStagePlugin, EmailCacheStagePlugin {

    private final String userId;
    private final Storage storage;

    public AutocryptPlugin(final String userId, final Storage storage) {
        this.userId = userId;
        this.storage = storage;
    }

    @Override
    public ListenableFuture<Email> onBuildEmail(final Email email) {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder()
                        .userId(userId)
                        .storage(storage)
                        .ioExecutorService(muaSession.getIoExecutorService())
                        .build();
        return autocryptClient.injectAutocryptHeader(email);
    }

    @Override
    public void onCacheEmail(final Email email) {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder()
                        .userId(userId)
                        .storage(storage)
                        .ioExecutorService(MoreExecutors.newDirectExecutorService())
                        .build();
        try {
            autocryptClient.processAutocryptHeader(email).get();
        } catch (final ExecutionException e) {
            final Throwable throwable = Throwables.getRootCause(e);
            throw new RuntimeException("Unable to process autocrypt headers", throwable);
        } catch (InterruptedException ignored) {
        }
    }
}
