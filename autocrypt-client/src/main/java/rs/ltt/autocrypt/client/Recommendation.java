package rs.ltt.autocrypt.client;

import com.google.common.base.Preconditions;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class Recommendation {

    public static final Recommendation DISABLE =
            new Recommendation(Decision.DISABLE, null, EncryptionPreference.NO_PREFERENCE);
    private final Decision decision;
    private final PGPPublicKeyRing publicKey;
    private final EncryptionPreference encryptionPreference;

    private Recommendation(
            final Decision decision,
            final PGPPublicKeyRing publicKey,
            final EncryptionPreference encryptionPreference) {
        this.decision = decision;
        this.publicKey = publicKey;
        this.encryptionPreference = encryptionPreference;
    }

    public static Recommendation discourage(final PGPPublicKeyRing publicKey) {
        Preconditions.checkNotNull(publicKey);
        return new Recommendation(
                Decision.DISCOURAGE, publicKey, EncryptionPreference.NO_PREFERENCE);
    }

    public static Recommendation available(
            final PGPPublicKeyRing publicKey, final EncryptionPreference encryptionPreference) {
        Preconditions.checkNotNull(publicKey);
        return new Recommendation(Decision.AVAILABLE, publicKey, encryptionPreference);
    }

    public Decision getDecision() {
        return decision;
    }

    public PGPPublicKeyRing getPublicKey() {
        return publicKey;
    }

    public EncryptionPreference getEncryptionPreference() {
        return encryptionPreference;
    }
}
