package rs.ltt.autocrypt.jmap;

import com.google.common.base.Preconditions;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.io.Closeables;
import com.google.common.net.MediaType;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rs.ltt.autocrypt.client.AbstractAutocryptClient;
import rs.ltt.autocrypt.client.DefaultSettings;
import rs.ltt.autocrypt.client.Recommendation;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.storage.AccountState;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.autocrypt.jmap.mime.MimeTransformer;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;
import rs.ltt.jmap.common.entity.EmailBodyPart;
import rs.ltt.jmap.common.entity.IdentifiableEmailWithAddresses;
import rs.ltt.jmap.common.util.MediaTypes;
import rs.ltt.jmap.mua.util.EmailUtil;

@SuppressWarnings("UnstableApiUsage")
public class AutocryptClient extends AbstractAutocryptClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutocryptClient.class);

    protected AutocryptClient(
            String userId,
            Storage storage,
            ListeningExecutorService ioExecutorService,
            DefaultSettings defaultSettings) {
        super(userId, storage, ioExecutorService, defaultSettings);
    }

    public static Builder builder() {
        return new Builder();
    }

    public ListenableFuture<List<Recommendation>> getRecommendations(
            final IdentifiableEmailWithAddresses email, final boolean isReplyToEncrypted) {
        if (email.getBcc() != null && !email.getBcc().isEmpty()) {
            return Futures.immediateFuture(ImmutableList.of(Recommendation.DISABLE));
        }
        return getRecommendationsForAddresses(recipients(email), isReplyToEncrypted);
    }

    public ListenableFuture<List<Recommendation>> getRecommendationsForAddresses(
            final Collection<EmailAddress> addresses, final boolean isReplyToEncrypted) {
        return super.getRecommendations(
                Collections2.transform(addresses, EmailAddress::getEmail), isReplyToEncrypted);
    }

    public static List<EmailAddress> recipients(final IdentifiableEmailWithAddresses email) {
        if (email.getBcc() != null && !email.getBcc().isEmpty()) {
            throw new IllegalArgumentException("Email contains Bcc recipients");
        }
        final ImmutableList.Builder<EmailAddress> addressBuilder = new ImmutableList.Builder<>();
        if (email.getTo() != null) {
            addressBuilder.addAll(email.getTo());
        }
        if (email.getCc() != null) {
            addressBuilder.addAll(email.getCc());
        }
        final List<EmailAddress> addresses = addressBuilder.build();
        if (Iterables.any(addresses, a -> a == null || a.getEmail() == null)) {
            throw new IllegalArgumentException("Some recipients do not have email addresses");
        }
        return addresses;
    }

    public ListenableFuture<Email> injectAutocryptHeader(final Email email) {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> injectAutocryptHeader(email, accountState),
                MoreExecutors.directExecutor());
    }

    private Email injectAutocryptHeader(final Email email, final AccountState accountState) {
        if (!accountState.isEnabled()) {
            return email;
        }
        final AutocryptHeader header;
        final List<EmailAddress> from = email.getFrom();
        if (from != null && from.size() == 1) {
            final String address = from.get(0).getEmail();
            if (address == null) {
                throw new IllegalArgumentException("EmailAddress did not contain valid address");
            }
            header = this.getAutocryptHeader(address, accountState);
        } else {
            header = this.getAutocryptHeader(accountState);
        }
        return injectAutocryptHeader(email, header);
    }

    private static Email injectAutocryptHeader(final Email email, final AutocryptHeader header) {
        if (header != null) {
            return email.toBuilder().autocrypt(header.toHeaderValue()).build();
        } else {
            return email;
        }
    }

    public ListenableFuture<AutocryptHeader> getAutocryptHeader(final EmailAddress from) {
        final String address = from.getEmail();
        if (address == null) {
            throw new IllegalArgumentException("EmailAddress did not contain valid address");
        }
        return getAutocryptHeader(address);
    }

    public ListenableFuture<EncryptionResult> encrypt(
            final Collection<EmailAddress> addresses,
            final Collection<BodyPartTuple> bodyParts,
            final OutputStream outputStream) {
        final Collection<String> recipients =
                Collections2.transform(addresses, EmailAddress::getEmail);
        final ListenableFuture<List<AutocryptHeader>> gossipHeaderFuture =
                getGossipHeaders(recipients);
        final ListenableFuture<EncryptionStream> encryptionStreamFuture =
                encrypt(recipients, outputStream);
        return Futures.whenAllSucceed(gossipHeaderFuture, encryptionStreamFuture)
                .callAsync(
                        () -> {
                            final EncryptionStream encryptionStream = encryptionStreamFuture.get();
                            final List<AutocryptHeader> gossipHeader = gossipHeaderFuture.get();
                            final EncryptionResult encryptionResult =
                                    writeMimeMessage(bodyParts, gossipHeader, encryptionStream);
                            // unfortunately EncryptionStream doesn't close the underlying stream
                            Closeables.close(outputStream, true);
                            return Futures.immediateFuture(encryptionResult);
                        },
                        CRYPTO_EXECUTOR);
    }

    private EncryptionResult writeMimeMessage(
            final Collection<BodyPartTuple> bodyParts,
            final List<AutocryptHeader> gossipHeader,
            final EncryptionStream encryptionStream)
            throws IOException {
        MimeTransformer.transform(bodyParts, gossipHeader, encryptionStream);
        encryptionStream.flush();
        encryptionStream.close();
        return encryptionStream.getResult();
    }

    public ListenableFuture<Void> processAutocryptHeader(final Email email) {
        final List<String> autocryptHeaders = email.getAutocrypt();
        final List<EmailAddress> from = email.getFrom();
        if (autocryptHeaders == null || from == null || from.size() != 1) {
            return Futures.immediateVoidFuture();
        }
        final String fromAddress =
                Objects.requireNonNull(Iterables.getOnlyElement(from)).getEmail();

        if (fromAddress == null) {
            return Futures.immediateVoidFuture();
        }

        final EmailBodyPart bodyStructure = email.getBodyStructure();
        final MediaType contentType = bodyStructure == null ? null : bodyStructure.getMediaType();
        if (contentType == null) {
            LOGGER.warn(
                    "E-mail did not have Content-Type. 'bodyStructure' needs to be requested"
                            + " explicitly");
        } else if (contentType.is(MediaTypes.MULTIPART_REPORT)) {
            LOGGER.debug(
                    "E-mail was {}. Do not process AutocryptHeader", MediaTypes.MULTIPART_REPORT);
            return Futures.immediateVoidFuture();
        }

        final Instant effectiveDate = EmailUtil.getEffectiveDate(email);
        return this.processAutocryptHeaders(fromAddress, effectiveDate, autocryptHeaders);
    }

    public static class Builder {

        private String userId;
        private Storage storage = new InMemoryStorage();
        private ListeningExecutorService ioExecutorService =
                MoreExecutors.newDirectExecutorService();
        private DefaultSettings defaultSettings = DefaultSettings.DEFAULT;

        private Builder() {}

        public Builder userId(final String userId) {
            this.userId = userId;
            return this;
        }

        public Builder storage(final Storage storage) {
            Preconditions.checkArgument(storage != null, "Storage must not be null");
            this.storage = storage;
            return this;
        }

        public Builder ioExecutorService(final ListeningExecutorService ioExecutorService) {
            Preconditions.checkArgument(
                    ioExecutorService != null, "ioExecutorService must not be null");
            this.ioExecutorService = ioExecutorService;
            return this;
        }

        public Builder defaultSettings(final DefaultSettings defaultSettings) {
            Preconditions.checkArgument(
                    defaultSettings != null, "defaultSettings must not be null");
            this.defaultSettings = defaultSettings;
            return this;
        }

        public AutocryptClient build() {
            Preconditions.checkState(this.userId != null, "UserId must not be null");
            return new AutocryptClient(
                    this.userId, this.storage, this.ioExecutorService, this.defaultSettings);
        }
    }
}
