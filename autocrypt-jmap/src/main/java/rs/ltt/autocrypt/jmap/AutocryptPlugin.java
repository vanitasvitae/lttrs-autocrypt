package rs.ltt.autocrypt.jmap;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.pgpainless.encryption_signing.EncryptionResult;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.jmap.client.blob.OutputStreamUpload;
import rs.ltt.jmap.client.blob.Progress;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;
import rs.ltt.jmap.common.entity.Upload;
import rs.ltt.jmap.mua.plugin.EmailBuildStagePlugin;
import rs.ltt.jmap.mua.plugin.EmailCacheStagePlugin;
import rs.ltt.jmap.mua.plugin.EventCallback;
import rs.ltt.jmap.mua.service.BinaryService;
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

    public ListenableFuture<Upload> encrypt(
            final Collection<EmailAddress> addresses,
            final Collection<BodyPartTuple> bodyParts,
            final Progress progress) {
        final OutputStreamUpload outputStreamUpload = OutputStreamUpload.of(MediaType.OCTET_STREAM);
        final ListenableFuture<Upload> uploadFuture =
                getService(BinaryService.class).upload(outputStreamUpload, progress);
        final ListenableFuture<EncryptionResult> encryptionResultFuture;
        try {
            encryptionResultFuture =
                    getAutocryptClient()
                            .encrypt(addresses, bodyParts, outputStreamUpload.getOutputStream());
        } catch (final IOException e) {
            return Futures.immediateFailedFuture(e);
        }
        return Futures.transformAsync(
                uploadFuture,
                upload -> {
                    return Futures.transform(
                            encryptionResultFuture,
                            encryptionResult -> {
                                return upload;
                            },
                            MoreExecutors.directExecutor());
                },
                MoreExecutors.directExecutor());
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
