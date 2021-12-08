package rs.ltt.autocrypt.client;

import com.google.common.base.Preconditions;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import rs.ltt.autocrypt.client.state.PreRecommendation;

public class Recommendation {

    private final Decision decision;
    private final PGPPublicKeyRing publicKey;

    public Recommendation(Decision decision, PGPPublicKeyRing publicKey) {
        this.decision = decision;
        this.publicKey = publicKey;
    }

    public static Recommendation encrypt(final PreRecommendation preRecommendation) {
        Preconditions.checkArgument(preRecommendation.getDecision() != Decision.DISABLE);
        return new Recommendation(Decision.ENCRYPT, preRecommendation.getPublicKey());
    }

    public static Recommendation copyOf(PreRecommendation preRecommendation) {
        return new Recommendation(
                preRecommendation.getDecision(), preRecommendation.getPublicKey());
    }
}
