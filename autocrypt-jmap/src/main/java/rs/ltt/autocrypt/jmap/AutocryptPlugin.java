package rs.ltt.autocrypt.jmap;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import org.checkerframework.checker.nullness.qual.NonNull;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.mua.plugin.EmailBuildStagePlugin;
import rs.ltt.jmap.mua.plugin.EmailCacheStagePlugin;
import rs.ltt.jmap.mua.plugin.EventCallback;
import rs.ltt.jmap.mua.service.MuaSession;
import rs.ltt.jmap.mua.service.PluginService;

public class AutocryptPlugin extends PluginService.Plugin {

    private final String userId;
    private final Storage storage;

    private final EmailCacheStagePlugin emailCacheStagePlugin = AutocryptPlugin.this::onCacheEmail;
    private AutocryptClient autocryptClient;
    private final EmailBuildStagePlugin emailBuildStagePlugin = AutocryptPlugin.this::onBuildEmail;

    public AutocryptPlugin(final String userId, final Storage storage) {
        this.userId = userId;
        this.storage = storage;
    }

    @Override
    protected Collection<EventCallback> install(MuaSession muaSession) {
        super.install(muaSession);
        this.autocryptClient =
                AutocryptClient.builder()
                        .userId(userId)
                        .storage(storage)
                        .ioExecutorService(muaSession.getIoExecutorService())
                        .build();
        return ImmutableList.of(emailBuildStagePlugin, emailCacheStagePlugin);
    }

    @NonNull
    private ListenableFuture<Email> onBuildEmail(final Email email) {
        return getAutocryptClient().injectAutocryptHeader(email);
    }

    public AutocryptClient getAutocryptClient() {
        final AutocryptClient autocryptClient = this.autocryptClient;
        if (autocryptClient == null) {
            throw new IllegalStateException("Plugin has not been installed yet");
        }
        return autocryptClient;
    }

    private void onCacheEmail(final Email email) {
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
