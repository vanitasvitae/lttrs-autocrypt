package rs.ltt.autocrypt.client.storage;

import java.time.Instant;
import java.util.HashMap;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class InMemoryStorage implements Storage {

    private final HashMap<String, PeerState> peers = new HashMap<>();
    private final HashMap<String, AccountState> accounts = new HashMap<>();

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
            final String address, final Instant effectiveDate, final byte[] publicKey) {
        final PeerState currentPeerState = peers.get(address);
        if (currentPeerState != null && effectiveDate.isBefore(currentPeerState.gossipTimestamp)) {
            return false;
        }
        if (currentPeerState == null) {
            peers.put(address, PeerState.freshGossip(effectiveDate, publicKey));
        } else {
            peers.put(address, currentPeerState.updateGossip(effectiveDate, publicKey));
        }
        return true;
    }

    @Override
    public rs.ltt.autocrypt.client.storage.PeerState getPeerState(final String address) {
        return this.peers.get(address);
    }

    @Override
    public AccountState getAccountState(final String userId) {
        return this.accounts.get(userId);
    }

    @Override
    public void setAccountState(final String userId, final AccountState accountState) {
        this.accounts.put(userId, accountState);
    }

    private static class PeerState implements rs.ltt.autocrypt.client.storage.PeerState {
        private final Instant lastSeen;
        private final Instant autocryptTimestamp;
        private final byte[] publicKey;
        private final EncryptionPreference encryptionPreference;
        private final Instant gossipTimestamp;
        private final byte[] gossipKey;

        private PeerState(
                Instant lastSeen,
                Instant autocryptTimestamp,
                byte[] publicKey,
                EncryptionPreference encryptionPreference,
                Instant gossipTimestamp,
                byte[] gossipKey) {
            this.lastSeen = lastSeen;
            this.autocryptTimestamp = autocryptTimestamp;
            this.publicKey = publicKey;
            this.encryptionPreference = encryptionPreference;
            this.gossipTimestamp = gossipTimestamp;
            this.gossipKey = gossipKey;
        }

        private static PeerState fresh(final Instant lastSeen) {
            return new PeerState(
                    lastSeen,
                    Instant.EPOCH,
                    null,
                    EncryptionPreference.NO_PREFERENCE,
                    Instant.EPOCH,
                    null);
        }

        private static PeerState freshGossip(
                final Instant gossipTimestamp, final byte[] publicKey) {
            return new PeerState(
                    Instant.EPOCH,
                    Instant.EPOCH,
                    null,
                    EncryptionPreference.NO_PREFERENCE,
                    gossipTimestamp,
                    publicKey);
        }

        public PeerState updateLastSeen(final Instant lastSeen) {
            return new PeerState(
                    lastSeen,
                    this.autocryptTimestamp,
                    this.publicKey,
                    this.encryptionPreference,
                    this.gossipTimestamp,
                    this.gossipKey);
        }

        public PeerState updateAutocrypt(
                final Instant autocryptTimestamp,
                final byte[] publicKey,
                final EncryptionPreference preference) {
            return new PeerState(
                    this.lastSeen,
                    autocryptTimestamp,
                    publicKey,
                    preference,
                    this.gossipTimestamp,
                    this.gossipKey);
        }

        public PeerState updateGossip(final Instant gossipTimestamp, final byte[] publicKey) {
            return new PeerState(
                    this.lastSeen,
                    this.autocryptTimestamp,
                    this.publicKey,
                    this.encryptionPreference,
                    gossipTimestamp,
                    publicKey);
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
        public Instant getGossipTimestamp() {
            return this.gossipTimestamp;
        }

        @Override
        public byte[] getPublicKey() {
            return this.publicKey;
        }

        @Override
        public byte[] getGossipKey() {
            return this.gossipKey;
        }

        @Override
        public EncryptionPreference getEncryptionPreference() {
            return this.encryptionPreference;
        }
    }
}
