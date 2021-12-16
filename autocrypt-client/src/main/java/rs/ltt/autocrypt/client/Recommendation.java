package rs.ltt.autocrypt.client;

import com.google.common.base.Preconditions;
import com.google.common.collect.Collections2;
import java.util.Collection;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import rs.ltt.autocrypt.client.state.PreRecommendation;

public class Recommendation {

    public static final Recommendation DISABLE = new Recommendation(Decision.DISABLE, null);
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

    public static Decision combine(final Collection<Recommendation> recommendations) {
        return Decision.combine(
                Collections2.transform(recommendations, Recommendation::getDecision));
    }

    public Decision getDecision() {
        return decision;
    }

    public PGPPublicKeyRing getPublicKey() {
        return publicKey;
    }
}
