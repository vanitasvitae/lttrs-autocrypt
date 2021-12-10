package rs.ltt.autocrypt.client;

import static java.util.Arrays.asList;

import com.google.common.collect.Collections2;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.client.state.PeerStateManager;
import rs.ltt.autocrypt.client.state.PreRecommendation;
import rs.ltt.autocrypt.client.storage.AccountState;
import rs.ltt.autocrypt.client.storage.ImmutableAccountState;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;
import rs.ltt.autocrypt.client.storage.Storage;

public class AutocryptClient {

    private final ListeningExecutorService ioExecutorService =
            MoreExecutors.listeningDecorator(Executors.newSingleThreadExecutor());

    private final Storage storage;
    private final PeerStateManager peerStateManager;
    private final String userId;
    private final DefaultSettings defaultSettings;

    private AccountState accountState;

    public AutocryptClient(final String userdId) {
        this(userdId, new InMemoryStorage());
    }

    public AutocryptClient(final String userId, final Storage storage) {
        this(userId, storage, DefaultSettings.DEFAULT);
    }

    public AutocryptClient(
            final String userId, final Storage storage, final DefaultSettings defaultSettings) {
        this.storage = storage;
        this.peerStateManager = new PeerStateManager(storage);
        this.userId = userId;
        this.defaultSettings = defaultSettings;
    }

    // TODO this can be removed once PGPainless can take iterable<>
    private static PGPPublicKeyRingCollection of(final Collection<PGPPublicKeyRing> keyRings) {
        try {
            return new PGPPublicKeyRingCollection(keyRings);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public ListenableFuture<Void> processAutocryptHeader(
            final String from, final Instant effectiveDate, final String autocryptHeader) {
        return processAutocryptHeaders(from, effectiveDate, Collections.singleton(autocryptHeader));
    }

    public ListenableFuture<Void> processAutocryptHeaders(
            final String from,
            final Instant effectiveDate,
            final Collection<String> autocryptHeaders) {
        return Futures.submit(
                () ->
                        peerStateManager.processAutocryptHeaders(
                                from, effectiveDate, autocryptHeaders),
                ioExecutorService);
    }

    public ListenableFuture<AutocryptHeader> getAutocryptHeader() {
        return Futures.transform(
                getAccountStateFuture(), this::getAutocryptHeader, MoreExecutors.directExecutor());
    }

    private ListenableFuture<AccountState> getAccountStateFuture() {
        if (accountState != null) {
            return Futures.immediateFuture(accountState);
        }
        return Futures.submit(this::getAccountState, ioExecutorService);
    }

    private AutocryptHeader getAutocryptHeader(final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        return AutocryptHeader.of(secretKeyRing, accountState.getEncryptionPreference());
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
            final byte[] keyData = PGPKeyRings.keyData(secretKeyRing);
            final AccountState freshAccountState =
                    ImmutableAccountState.builder()
                            .isEnabled(defaultSettings.isEnabled())
                            .encryptionPreference(defaultSettings.getEncryptionPreference())
                            .secretKey(keyData)
                            .build();
            storeAccountState(freshAccountState);
            return freshAccountState;
        }
    }

    private void storeAccountState(final AccountState accountState) {
        this.storage.setAccountState(userId, accountState);
        this.accountState = accountState;
    }

    public ListenableFuture<DecryptionStream> decrypt(final InputStream inputStream) {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> decrypt(inputStream, accountState),
                MoreExecutors.directExecutor());
    }

    private DecryptionStream decrypt(
            final InputStream inputStream, final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        // TODO do we want to add sender verification?
        final ConsumerOptions consumerOptions =
                new ConsumerOptions().addDecryptionKey(secretKeyRing);
        try {
            return PGPainless.decryptAndOrVerify()
                    .onInputStream(inputStream)
                    .withOptions(consumerOptions);
        } catch (final PGPException | IOException e) {
            throw new IllegalStateException("Unable to create DecryptionStream", e);
        }
    }

    public ListenableFuture<EncryptionStream> encrypt(
            final OutputStream outputStream, final Collection<String> recipients) {
        return Futures.transformAsync(
                getAccountStateFuture(),
                accountState -> encrypt(outputStream, recipients, accountState),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<EncryptionStream> encrypt(
            final OutputStream outputStream,
            final Collection<String> recipients,
            final AccountState accountState) {
        return Futures.transform(
                getRecommendations(recipients),
                recommendations -> {
                    if (Recommendation.combine(recommendations) == Decision.DISABLE) {
                        throw new IllegalArgumentException(
                                "Not all recipients have valid public keys");
                    }
                    final Collection<PGPPublicKeyRing> publicKeys =
                            Collections2.transform(recommendations, Recommendation::getPublicKey);
                    return createEncryptionStream(outputStream, publicKeys, accountState);
                },
                MoreExecutors.directExecutor());
    }

    private EncryptionStream createEncryptionStream(
            final OutputStream outputStream,
            final Collection<PGPPublicKeyRing> recipients,
            final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        final EncryptionOptions encryptionOptions =
                new EncryptionOptions().addRecipients(of(recipients));
        final SigningOptions signingOptions;
        try {
            signingOptions =
                    new SigningOptions()
                            .addInlineSignature(
                                    SecretKeyRingProtector.unprotectedKeys(),
                                    secretKeyRing,
                                    DocumentSignatureType.CANONICAL_TEXT_DOCUMENT);
        } catch (final PGPException e) {
            throw new IllegalStateException("Secret key is unable to generate signatures", e);
        }
        final ProducerOptions producerOptions =
                ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions)
                        .setAsciiArmor(true);
        try {
            return PGPainless.encryptAndOrSign()
                    .onOutputStream(outputStream)
                    .withOptions(producerOptions);
        } catch (final PGPException | IOException e) {
            throw new IllegalStateException("Unable to create EncryptionStream", e);
        }
    }

    public ListenableFuture<Void> setEncryptionPreference(final EncryptionPreference preference) {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> setEncryptionPreference(accountState, preference),
                ioExecutorService);
    }

    private Void setEncryptionPreference(
            final AccountState accountState, final EncryptionPreference preference) {
        final AccountState freshAccountState =
                ImmutableAccountState.builder()
                        .from(accountState)
                        .encryptionPreference(preference)
                        .build();
        storeAccountState(freshAccountState);
        return null;
    }

    public ListenableFuture<Recommendation> getRecommendation(
            final String address, final boolean isReplyToEncrypted) {
        return Futures.transformAsync(
                getAccountStateFuture(),
                accountState -> getRecommendation(address, isReplyToEncrypted, accountState),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<Recommendation> getRecommendation(
            final String address,
            final boolean isReplyToEncrypted,
            final AccountState accountState) {
        return Futures.transform(
                getPreliminaryRecommendation(address),
                preRecommendation ->
                        getRecommendation(
                                accountState,
                                isReplyToEncrypted,
                                Objects.requireNonNull(preRecommendation)),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<PreRecommendation> getPreliminaryRecommendation(final String address) {
        return Futures.submit(
                () -> peerStateManager.getPreliminaryRecommendation(address), ioExecutorService);
    }

    private static Recommendation getRecommendation(
            final AccountState accountState,
            final boolean isReplyToEncrypted,
            final PreRecommendation preRecommendation) {
        final Decision preliminaryDecision = preRecommendation.getDecision();
        if (asList(Decision.AVAILABLE, Decision.DISCOURAGE).contains(preliminaryDecision)
                && isReplyToEncrypted) {
            return Recommendation.encrypt(preRecommendation);
        }
        final boolean mutualPreference =
                accountState.getEncryptionPreference() == EncryptionPreference.MUTUAL
                        && preRecommendation.getEncryptionPreference()
                                == EncryptionPreference.MUTUAL;
        if (mutualPreference && preliminaryDecision == Decision.AVAILABLE) {
            return Recommendation.encrypt(preRecommendation);
        }
        return Recommendation.copyOf(preRecommendation);
    }

    public ListenableFuture<List<Recommendation>> getRecommendations(
            final Collection<String> addresses) {
        return getRecommendations(addresses, false);
    }

    public ListenableFuture<List<Recommendation>> getRecommendations(
            final Collection<String> addresses, final boolean isReplyToEncrypted) {
        return Futures.transformAsync(
                getAccountStateFuture(),
                accountState -> getRecommendations(addresses, isReplyToEncrypted, accountState),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<List<Recommendation>> getRecommendations(
            final Collection<String> addresses,
            final boolean isReplyToEncrypted,
            final AccountState accountState) {
        return Futures.allAsList(
                Collections2.transform(
                        addresses,
                        address -> getRecommendation(address, isReplyToEncrypted, accountState)));
    }
}
