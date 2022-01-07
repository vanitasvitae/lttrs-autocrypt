package rs.ltt.autocrypt.jmap;

import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import org.apache.james.mime4j.MimeException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.autocrypt.jmap.mime.AttachmentRetriever;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.autocrypt.jmap.mime.MimeTransformer;
import rs.ltt.autocrypt.jmap.util.HttpCalls;
import rs.ltt.jmap.client.blob.Download;
import rs.ltt.jmap.client.blob.OutputStreamUpload;
import rs.ltt.jmap.client.blob.Progress;
import rs.ltt.jmap.client.util.Closeables;
import rs.ltt.jmap.common.entity.*;
import rs.ltt.jmap.mua.plugin.EmailBuildStagePlugin;
import rs.ltt.jmap.mua.plugin.EmailCacheStagePlugin;
import rs.ltt.jmap.mua.plugin.EventCallback;
import rs.ltt.jmap.mua.service.BinaryService;
import rs.ltt.jmap.mua.service.EmailService;
import rs.ltt.jmap.mua.service.MuaSession;
import rs.ltt.jmap.mua.service.PluginService;

public class AutocryptPlugin extends PluginService.Plugin {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutocryptPlugin.class);

    private final String userId;
    private final Storage storage;

    private final EmailCacheStagePlugin emailCacheStagePlugin = AutocryptPlugin.this::onCacheEmail;
    private AutocryptClient autocryptClient;
    private final EmailBuildStagePlugin emailBuildStagePlugin = AutocryptPlugin.this::onBuildEmail;

    public AutocryptPlugin(final String userId, final Storage storage) {
        this.userId = userId;
        this.storage = storage;
    }

    public ListenableFuture<Upload> encryptAndUpload(
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
                upload ->
                        Futures.transform(
                                encryptionResultFuture,
                                encryptionResult -> {
                                    Preconditions.checkState(
                                            encryptionResult != null,
                                            "Encryption result was unexpectedly null");
                                    LOGGER.info(
                                            "Encrypted to {} recipients with {} and {} compression",
                                            encryptionResult.getRecipients().size(),
                                            encryptionResult.getEncryptionAlgorithm(),
                                            encryptionResult.getCompressionAlgorithm());
                                    return upload;
                                },
                                MoreExecutors.directExecutor()),
                MoreExecutors.directExecutor());
    }

    public AutocryptClient getAutocryptClient() {
        final AutocryptClient autocryptClient = this.autocryptClient;
        if (autocryptClient == null) {
            throw new IllegalStateException("Plugin has not been installed yet");
        }
        return autocryptClient;
    }

    public ListenableFuture<Email> downloadAndDecrypt(
            final Downloadable downloadable, final AttachmentRetriever attachmentRetriever) {
        final ListenableFuture<Download> downloadFuture =
                getService(BinaryService.class).download(downloadable);
        return Futures.transformAsync(
                downloadFuture,
                download ->
                        downloadAndDecrypt(
                                downloadable.getBlobId(),
                                attachmentRetriever,
                                Objects.requireNonNull(download)),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<Email> downloadAndDecrypt(
            final String blobId,
            final AttachmentRetriever attachmentRetriever,
            final Download download) {
        final ListenableFuture<DecryptionStream> streamFuture =
                getAutocryptClient().decrypt(download.getInputStream());
        final ListenableFuture<Email> emailFuture =
                Futures.transformAsync(
                        streamFuture,
                        ds -> this.parseMimeMessage(ds, blobId, attachmentRetriever),
                        AutocryptClient.CRYPTO_EXECUTOR);
        HttpCalls.cancelCallOnCancel(emailFuture, download.getCall());
        return emailFuture;
    }

    @NonNull
    private ListenableFuture<Email> parseMimeMessage(
            final DecryptionStream decryptionStream,
            final String blobId,
            final AttachmentRetriever attachmentRetriever) {
        final Email email;
        try {
            email = MimeTransformer.transform(decryptionStream, blobId, attachmentRetriever);
        } catch (final IOException | MimeException e) {
            return Futures.immediateFailedFuture(e);
        }
        Closeables.closeQuietly(decryptionStream);
        final OpenPgpMetadata result = decryptionStream.getResult();
        LOGGER.info(
                "Successfully decrypted email to {} recipients with {} and {} compression",
                result.getRecipientKeyIds().size(),
                result.getSymmetricKeyAlgorithm(),
                result.getCompressionAlgorithm());
        return Futures.immediateFuture(email);
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

    public ListenableFuture<String> storeSetupMessage(final String passphrase) {
        return Futures.transformAsync(
                getAutocryptClient().exportSecretKey(passphrase),
                setupMessage -> {
                    final EmailAddress emailAddress = EmailAddress.builder().email(userId).build();
                    final Email email =
                            SetupMessage.ofAttachment(setupMessage).toBuilder()
                                    .from(emailAddress)
                                    .to(emailAddress)
                                    .build();
                    return storeSetupMessage(email);
                },
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<String> storeSetupMessage(final Email setupMessage) {
        return getService(EmailService.class).store(setupMessage, Role.SENT);
    }
}
