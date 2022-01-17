package rs.ltt.autocrypt.client.state;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rs.ltt.autocrypt.client.Addresses;
import rs.ltt.autocrypt.client.PGPKeyRings;
import rs.ltt.autocrypt.client.storage.PeerState;
import rs.ltt.autocrypt.client.storage.Storage;

public class PeerStateManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(PeerStateManager.class);

    private static final Duration AUTOCRYPT_HEADER_EXPIRY = Duration.ofDays(35);

    private final Storage storage;

    public PeerStateManager(final Storage storage) {
        this.storage = storage;
    }

    public void processAutocryptHeaders(
            final String from,
            final Instant effectiveDate,
            final Collection<String> autocryptHeaders) {
        if (storage.updateLastSeen(Addresses.normalize(from), effectiveDate)) {
            final PeerStateUpdate peerStateUpdate;
            try {
                peerStateUpdate =
                        PeerStateUpdate.builder(from, effectiveDate)
                                .addAll(autocryptHeaders)
                                .build();
            } catch (final IllegalStateException e) {
                return;
            }
            final PGPPublicKeyRing publicKeyRing =
                    PGPKeyRings.readPublicKeyRing(peerStateUpdate.getKeyData());
            if (PGPKeyRings.isSuitableForEncryption(publicKeyRing)) {
                storage.updateAutocrypt(
                        peerStateUpdate.getFrom(),
                        peerStateUpdate.getEffectiveDate(),
                        peerStateUpdate.getKeyData(),
                        peerStateUpdate.getEncryptionPreference());
            }
        }
    }

    public void processGossipHeader(
            final Collection<String> recipients, final Collection<GossipUpdate> gossipUpdates) {
        for (final GossipUpdate gossipUpdate : gossipUpdates) {
            if (recipients.contains(gossipUpdate.getFrom())) {
                final PGPPublicKeyRing publicKeyRing =
                        PGPKeyRings.readPublicKeyRing(gossipUpdate.getKeyData());
                if (PGPKeyRings.isSuitableForEncryption(publicKeyRing)) {
                    storage.updateGossip(
                            gossipUpdate.getFrom(),
                            gossipUpdate.getEffectiveDate(),
                            gossipUpdate.getKeyData());
                }
            } else {
                LOGGER.warn(
                        "{} did not appear in list of recipients {}",
                        gossipUpdate.getFrom(),
                        recipients);
            }
        }
    }

    public PreRecommendation getPreliminaryRecommendation(final String address) {
        final PeerState peerState = storage.getPeerState(Addresses.normalize(address));
        if (peerState == null) {
            return PreRecommendation.DISABLE;
        }
        final PGPPublicKeyRing publicKey = PGPKeyRings.readPublicKeyRing(peerState.getPublicKey());
        final PGPPublicKeyRing gossipKey = PGPKeyRings.readPublicKeyRing(peerState.getGossipKey());
        if (publicKey == null && gossipKey == null) {
            return PreRecommendation.DISABLE;
        }
        if (publicKey == null) {
            return PreRecommendation.discourage(gossipKey);
        }
        final Instant lastSeen = peerState.getLastSeen();
        final Instant autocryptTimestamp = peerState.getAutocryptTimestamp();
        if (autocryptTimestamp.isAfter(lastSeen.minus(AUTOCRYPT_HEADER_EXPIRY))) {
            return PreRecommendation.available(publicKey, peerState.getEncryptionPreference());
        } else {
            return PreRecommendation.discourage(publicKey);
        }
    }
}
