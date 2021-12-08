package rs.ltt.autocrypt.client;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.state.PeerStateManager;
import rs.ltt.autocrypt.client.storage.AccountState;
import rs.ltt.autocrypt.client.storage.ImmutableAccountState;
import rs.ltt.autocrypt.client.storage.Storage;

public class AutocryptClient {

    private final Storage storage;
    private final PeerStateManager peerStateManager;
    private final String userId;
    private final DefaultSettings defaultSettings;

    private AccountState accountState;

    public AutocryptClient(final Storage storage, final String userId) {
        this(storage, userId, DefaultSettings.DEFAULT);
    }

    public AutocryptClient(
            final Storage storage, final String userId, final DefaultSettings defaultSettings) {
        this.storage = storage;
        this.peerStateManager = new PeerStateManager(storage);
        this.userId = userId;
        this.defaultSettings = defaultSettings;
    }

    public ListenableFuture<AutocryptHeader> getAutocryptHeader() {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> {
                    final PGPSecretKeyRing secretKeyRing;
                    try {
                        secretKeyRing =
                                PGPainless.readKeyRing().secretKeyRing(accountState.getSecretKey());
                    } catch (final IOException e) {
                        throw new IllegalStateException(
                                "Retrieved invalid secret key from storage", e);
                    }
                    return AutocryptHeader.of(
                            secretKeyRing, accountState.getEncryptionPreference());
                },
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<AccountState> getAccountStateFuture() {
        if (accountState != null) {
            return Futures.immediateFuture(accountState);
        }
        return Futures.submit(this::getAccountState, MoreExecutors.directExecutor());
    }

    private AccountState getAccountState()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        synchronized (AutocryptClient.class) {
            if (this.accountState != null) {
                return this.accountState;
            }
            final AccountState accountState = storage.getAccountState(this.userId);
            if (accountState != null) {
                this.accountState = accountState;
                return accountState;
            }
            final PGPSecretKeyRing secretKeyRing =
                    PGPainless.generateKeyRing().simpleEcKeyRing(String.format("<%s>", userId));
            final byte[] keyData = PGPPublicKeyRings.keyData(secretKeyRing);
            final AccountState freshAccountState =
                    ImmutableAccountState.builder()
                            .isEnabled(defaultSettings.isEnabled())
                            .encryptionPreference(defaultSettings.getEncryptionPreference())
                            .secretKey(keyData)
                            .build();
            this.storage.setAccountState(userId, freshAccountState);
            this.accountState = freshAccountState;
            return freshAccountState;
        }
    }
}
