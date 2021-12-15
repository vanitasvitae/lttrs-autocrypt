package rs.ltt.autocrypt.jmap;

import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import java.time.Instant;
import java.util.List;
import rs.ltt.autocrypt.client.AbstractAutocryptClient;
import rs.ltt.autocrypt.client.DefaultSettings;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;
import rs.ltt.jmap.mua.util.EmailUtil;

public class AutocryptClient extends AbstractAutocryptClient {

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

    public ListenableFuture<AutocryptHeader> getAutocryptHeader(final EmailAddress from) {
        final String address = from.getEmail();
        if (address == null) {
            throw new IllegalArgumentException("EmailAddress did not contain valid address");
        }
        return getAutocryptHeader(address);
    }

    public ListenableFuture<Email> injectAutocryptHeader(final Email email) {
        final ListenableFuture<AutocryptHeader> headerFuture;
        final List<EmailAddress> from = email.getFrom();
        if (from != null && from.size() == 1) {
            headerFuture = this.getAutocryptHeader(from.get(0));
        } else {
            headerFuture = this.getAutocryptHeader();
        }
        return Futures.transform(
                headerFuture,
                header -> injectAutocryptHeader(email, header),
                MoreExecutors.directExecutor());
    }

    private static Email injectAutocryptHeader(final Email email, final AutocryptHeader header) {
        if (header != null) {
            return email.toBuilder().autocrypt(header.toHeaderValue()).build();
        } else {
            return email;
        }
    }

    public ListenableFuture<Void> processAutocryptHeader(final Email email) {
        final List<EmailAddress> from = email.getFrom();
        if (from.size() != 1) {
            return Futures.immediateVoidFuture();
        }
        final String fromAddress = from.get(0).getEmail();
        final Instant effectiveDate = EmailUtil.getEffectiveDate(email);
        return this.processAutocryptHeaders(fromAddress, effectiveDate, email.getAutocrypt());
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
