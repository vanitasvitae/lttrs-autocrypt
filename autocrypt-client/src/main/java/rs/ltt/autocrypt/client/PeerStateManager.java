package rs.ltt.autocrypt.client;

import java.time.Instant;
import java.util.Collection;
import rs.ltt.autocrypt.client.storage.Storage;

public class PeerStateManager {

    private final Storage storage;

    public PeerStateManager(final Storage storage) {
        this.storage = storage;
    }

    public void processAutocryptHeaders(
            final String from,
            final Instant effectiveDate,
            final Collection<String> autocryptHeaders) {
        if (storage.updateLastSeen(from, effectiveDate)) {
            final PeerStateUpdate peerStateUpdate;
            try {
                peerStateUpdate =
                        PeerStateUpdate.builder(from, effectiveDate)
                                .addAll(autocryptHeaders)
                                .build();
            } catch (final IllegalStateException e) {
                return;
            }
            // TODO validate key (check if signature checks out; has encryption capable sub key)
            storage.updateAutocrypt(
                    peerStateUpdate.getFrom(),
                    peerStateUpdate.getEffectiveDate(),
                    peerStateUpdate.getKeyData(),
                    peerStateUpdate.getEncryptionPreference());
        }
    }
}
