package rs.ltt.autocrypt.client;

import java.io.IOException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.key.info.KeyRingInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rs.ltt.autocrypt.client.storage.AccountState;

public final class PGPKeyRings {

    private static final Logger LOGGER = LoggerFactory.getLogger(PGPKeyRings.class);

    private PGPKeyRings() {
        throw new IllegalStateException("Do not instantiate me");
    }

    public static PGPPublicKeyRing readPublicKeyRing(final byte[] keyData) {
        if (keyData == null || keyData.length == 0) {
            return null;
        }
        try {
            return PGPainless.readKeyRing().publicKeyRing(keyData);
        } catch (IOException e) {
            return null;
        }
    }

    public static PGPSecretKeyRing readSecretKeyRing(final AccountState accountState) {
        return readSecretKeyRing(accountState.getSecretKey());
    }

    public static PGPSecretKeyRing readSecretKeyRing(final byte[] keyData) {
        try {
            return PGPainless.readKeyRing().secretKeyRing(keyData);
        } catch (final IOException e) {
            throw new IllegalStateException("Retrieved invalid secret key from storage", e);
        }
    }

    public static boolean isSuitableForEncryption(final PGPPublicKeyRing publicKeyRing) {
        if (publicKeyRing == null) {
            return false;
        }
        try {
            final KeyRingInfo keyInfo = PGPainless.inspectKeyRing(publicKeyRing);
            return keyInfo.getEncryptionSubkeys(EncryptionPurpose.COMMUNICATIONS).size() > 0;
        } catch (final Exception e) {
            LOGGER.info("cannot determine if PublicKeyRing is suitable for encryption", e);
            return false;
        }
    }

    public static byte[] keyData(final PGPKeyRing keyRing) {
        try {
            return keyRing.getEncoded();
        } catch (final IOException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
