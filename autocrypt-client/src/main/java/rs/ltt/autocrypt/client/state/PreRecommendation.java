package rs.ltt.autocrypt.client.state;

import com.google.common.base.Preconditions;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import rs.ltt.autocrypt.client.Decision;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class PreRecommendation {

    public static final PreRecommendation DISABLE =
            new PreRecommendation(Decision.DISABLE, null, EncryptionPreference.NO_PREFERENCE);
    private final Decision decision;
    private final PGPPublicKeyRing publicKey;
    private final EncryptionPreference encryptionPreference;

    private PreRecommendation(
            final Decision decision,
            final PGPPublicKeyRing publicKey,
            final EncryptionPreference encryptionPreference) {
        this.decision = decision;
        this.publicKey = publicKey;
        this.encryptionPreference = encryptionPreference;
    }

    public static PreRecommendation discourage(final PGPPublicKeyRing publicKey) {
        Preconditions.checkNotNull(publicKey);
        return new PreRecommendation(
                Decision.DISCOURAGE, publicKey, EncryptionPreference.NO_PREFERENCE);
    }

    public static PreRecommendation available(
            final PGPPublicKeyRing publicKey, final EncryptionPreference encryptionPreference) {
        Preconditions.checkNotNull(publicKey);
        return new PreRecommendation(Decision.AVAILABLE, publicKey, encryptionPreference);
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
