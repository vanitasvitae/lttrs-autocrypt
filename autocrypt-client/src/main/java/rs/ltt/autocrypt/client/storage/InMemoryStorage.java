package rs.ltt.autocrypt.client.storage;

import java.time.Instant;
import java.util.HashMap;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class InMemoryStorage implements Storage {

    private final HashMap<String, PeerState> peers = new HashMap<>();

    @Override
    public boolean updateLastSeen(final String address, final Instant effectiveDate) {
        final PeerState currentPeerState = peers.get(address);
        if (currentPeerState != null
                && effectiveDate.isBefore(currentPeerState.autocryptTimestamp)) {
            return false;
        }
        if (currentPeerState == null) {
            peers.put(address, PeerState.fresh(effectiveDate));
        } else if (effectiveDate.isAfter(currentPeerState.lastSeen)) {
            peers.put(address, currentPeerState.updateLastSeen(effectiveDate));
        }
        return true;
    }

    @Override
    public void updateAutocrypt(
            final String address,
            final Instant effectiveDate,
            final byte[] publicKey,
            final EncryptionPreference preference) {
        final PeerState currentPeerState = peers.get(address);
        if (currentPeerState == null) {
            return;
        }
        peers.put(address, currentPeerState.updateAutocrypt(effectiveDate, publicKey, preference));
    }

    @Override
    public boolean updateGossip(
            final String address, final Instant effectiveData, final byte[] publicKey) {
        return false;
    }

    @Override
    public rs.ltt.autocrypt.client.storage.PeerState getPeerState(final String address) {
        return this.peers.get(address);
    }

    private static class PeerState implements rs.ltt.autocrypt.client.storage.PeerState {
        private final Instant lastSeen;
        private final Instant autocryptTimestamp;
        private final byte[] publicKey;
        private final EncryptionPreference encryptionPreference;

        private PeerState(
                Instant lastSeen,
                Instant autocryptTimestamp,
                byte[] publicKey,
                EncryptionPreference encryptionPreference) {
            this.lastSeen = lastSeen;
            this.autocryptTimestamp = autocryptTimestamp;
            this.publicKey = publicKey;
            this.encryptionPreference = encryptionPreference;
        }

        private static PeerState fresh(final Instant lastSeen) {
            return new PeerState(lastSeen, Instant.EPOCH, null, EncryptionPreference.NO_PREFERENCE);
        }

        public PeerState updateLastSeen(final Instant lastSeen) {
            return new PeerState(
                    lastSeen, this.autocryptTimestamp, this.publicKey, this.encryptionPreference);
        }

        public PeerState updateAutocrypt(
                final Instant autocryptTimestamp,
                final byte[] publicKey,
                final EncryptionPreference preference) {
            return new PeerState(this.lastSeen, autocryptTimestamp, publicKey, preference);
        }

        @Override
        public Instant getLastSeen() {
            return this.lastSeen;
        }

        @Override
        public Instant getAutocryptTimestamp() {
            return this.autocryptTimestamp;
        }

        @Override
        public byte[] getPublicKey() {
            return this.publicKey;
        }

        @Override
        public EncryptionPreference getEncryptionPreference() {
            return this.encryptionPreference;
        }
    }
}
