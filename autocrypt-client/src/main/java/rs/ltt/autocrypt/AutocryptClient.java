package rs.ltt.autocrypt;

import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import rs.ltt.autocrypt.client.AbstractAutocryptClient;
import rs.ltt.autocrypt.client.DefaultSettings;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;

public class AutocryptClient extends AbstractAutocryptClient {

    private AutocryptClient(
            String userId,
            Storage storage,
            ListeningExecutorService ioExecutorService,
            DefaultSettings defaultSettings) {
        super(userId, storage, ioExecutorService, defaultSettings);
    }

    public static Builder builder() {
        return new Builder();
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
