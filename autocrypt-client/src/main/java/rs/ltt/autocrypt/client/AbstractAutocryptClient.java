package rs.ltt.autocrypt.client;

import static java.util.Arrays.asList;

import com.google.common.base.Optional;
import com.google.common.base.Strings;
import com.google.common.collect.Collections2;
import com.google.common.io.ByteStreams;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.MultiMap;
import org.pgpainless.util.Passphrase;
import rs.ltt.autocrypt.client.header.*;
import rs.ltt.autocrypt.client.state.PeerStateManager;
import rs.ltt.autocrypt.client.state.PreRecommendation;
import rs.ltt.autocrypt.client.storage.AccountState;
import rs.ltt.autocrypt.client.storage.ImmutableAccountState;
import rs.ltt.autocrypt.client.storage.Storage;

@SuppressWarnings({"Guava", "UnstableApiUsage"})
public abstract class AbstractAutocryptClient {

    public static final ListeningExecutorService CRYPTO_EXECUTOR =
            MoreExecutors.listeningDecorator(Executors.newFixedThreadPool(2));

    private final String userId;
    private final Storage storage;
    private final PeerStateManager peerStateManager;
    private final ListeningExecutorService ioExecutorService;
    private final DefaultSettings defaultSettings;

    private AccountState accountState;

    protected AbstractAutocryptClient(
            final String userId,
            final Storage storage,
            final ListeningExecutorService ioExecutorService,
            final DefaultSettings defaultSettings) {
        this.storage = storage;
        this.peerStateManager = new PeerStateManager(storage);
        this.userId = userId;
        this.ioExecutorService = ioExecutorService;
        this.defaultSettings = defaultSettings;
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

    protected ListenableFuture<AccountState> getAccountStateFuture() {
        if (accountState != null) {
            return Futures.immediateFuture(accountState);
        }
        return Futures.submit(this::getAccountState, ioExecutorService);
    }

    protected AutocryptHeader getAutocryptHeader(final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        return AutocryptHeader.of(secretKeyRing, accountState.getEncryptionPreference());
    }

    private AccountState getAccountState()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        synchronized (AbstractAutocryptClient.class) {
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

    public ListenableFuture<Void> ensureEverythingIsSetup() {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> {
                    if (accountState == null) {
                        throw new IllegalStateException("AccountState was null");
                    }
                    final byte[] secretKey = accountState.getSecretKey();
                    if (secretKey == null || secretKey.length == 0) {
                        throw new IllegalStateException("SecretKey was null");
                    }
                    return null;
                },
                MoreExecutors.directExecutor());
    }

    public ListenableFuture<AutocryptHeader> getAutocryptHeader(final String from) {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> getAutocryptHeader(from, accountState),
                MoreExecutors.directExecutor());
    }

    protected AutocryptHeader getAutocryptHeader(
            final String from, final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        return AutocryptHeader.of(from, secretKeyRing, accountState.getEncryptionPreference());
    }

    public ListenableFuture<DecryptionStream> decrypt(final InputStream inputStream) {
        return Futures.transformAsync(
                getAccountStateFuture(),
                accountState -> decrypt(inputStream, accountState),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<DecryptionStream> decrypt(
            final InputStream inputStream, final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        // TODO do we want to add sender verification?
        final ConsumerOptions consumerOptions =
                new ConsumerOptions().addDecryptionKey(secretKeyRing);
        try {
            return Futures.immediateFuture(
                    PGPainless.decryptAndOrVerify()
                            .onInputStream(inputStream)
                            .withOptions(consumerOptions));
        } catch (final PGPException | IOException e) {
            return Futures.immediateFailedFuture(e);
        }
    }

    public ListenableFuture<EncryptionStream> encrypt(
            final Collection<String> recipients, final OutputStream outputStream) {
        return Futures.transformAsync(
                getAccountStateFuture(),
                accountState -> encrypt(recipients, outputStream, accountState),
                MoreExecutors.directExecutor());
    }

    private ListenableFuture<EncryptionStream> encrypt(
            final Collection<String> recipients,
            final OutputStream outputStream,
            final AccountState accountState) {
        return Futures.transformAsync(
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

    private ListenableFuture<EncryptionStream> createEncryptionStream(
            final OutputStream outputStream,
            final Collection<PGPPublicKeyRing> recipients,
            final AccountState accountState) {
        final PGPSecretKeyRing secretKeyRing = PGPKeyRings.readSecretKeyRing(accountState);
        final EncryptionOptions encryptionOptions =
                new EncryptionOptions()
                        .addRecipients(recipients)
                        .addRecipient(PGPainless.extractCertificate(secretKeyRing));
        final SigningOptions signingOptions;
        try {
            signingOptions =
                    new SigningOptions()
                            .addInlineSignature(
                                    SecretKeyRingProtector.unprotectedKeys(),
                                    secretKeyRing,
                                    DocumentSignatureType.CANONICAL_TEXT_DOCUMENT);
        } catch (final PGPException e) {
            return Futures.immediateFailedFuture(e);
        }
        final ProducerOptions producerOptions =
                ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions)
                        .setAsciiArmor(true);
        try {
            return Futures.immediateFuture(
                    PGPainless.encryptAndOrSign()
                            .onOutputStream(outputStream)
                            .withOptions(producerOptions));
        } catch (final PGPException | IOException e) {
            return Futures.immediateFailedFuture(e);
        }
    }

    public ListenableFuture<Void> setEnabled(final boolean enabled) {
        return Futures.transform(
                getAccountStateFuture(),
                accountState -> setEnabled(accountState, enabled),
                ioExecutorService);
    }

    public Void setEnabled(final AccountState accountState, final boolean enabled) {
        final AccountState freshAccountState =
                ImmutableAccountState.builder().from(accountState).isEnabled(enabled).build();
        storeAccountState(freshAccountState);
        return null;
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
        if (!accountState.isEnabled()) {
            return Futures.immediateFuture(Recommendation.DISABLE);
        }
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

    public ListenableFuture<String> exportSecretKey(final String passphrase) {
        return Futures.transformAsync(
                getAccountStateFuture(),
                accountState -> exportSecretKey(accountState, Strings.nullToEmpty(passphrase)),
                CRYPTO_EXECUTOR);
    }

    private ListenableFuture<String> exportSecretKey(
            final AccountState accountState, final String passphrase) {
        SetupCode.checkArgument(passphrase);
        final InputStream armoredSecretKeyStream;
        try {
            armoredSecretKeyStream = toAsciiArmorStream(accountState);
        } catch (IOException e) {
            return Futures.immediateFailedFuture(e);
        }
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final EncryptionOptions encryptionOptions =
                EncryptionOptions.encryptCommunications()
                        .addPassphrase(Passphrase.fromPassword(passphrase));
        final ProducerOptions producerOptions =
                ProducerOptions.encrypt(encryptionOptions).setAsciiArmor(false);
        final EncryptionStream encryptionStream;
        try {
            encryptionStream =
                    PGPainless.encryptAndOrSign()
                            .onOutputStream(byteArrayOutputStream)
                            .withOptions(producerOptions);
        } catch (final PGPException | IOException e) {
            return Futures.immediateFailedFuture(e);
        }
        try {
            ByteStreams.copy(armoredSecretKeyStream, encryptionStream);
            encryptionStream.flush();
            encryptionStream.close();
        } catch (final IOException e) {
            return Futures.immediateFailedFuture(e);
        }
        final PassphraseHint passphraseHint =
                new PassphraseHint(passphrase.substring(0, 2), PassphraseHint.Format.NUMERIC9X4);
        try {
            return Futures.immediateFuture(
                    ArmorUtils.toAsciiArmoredString(
                            byteArrayOutputStream.toByteArray(), passphraseHint.asHeader()));
        } catch (final IOException e) {
            return Futures.immediateFailedFuture(e);
        }
    }

    public InputStream toAsciiArmorStream(final AccountState accountState) throws IOException {
        return new ByteArrayInputStream(
                toAsciiArmor(accountState).getBytes(StandardCharsets.UTF_8));
    }

    private String toAsciiArmor(final AccountState accountState) throws IOException {
        final MultiMap<String, String> header = new MultiMap<>();
        header.put(
                Headers.AUTOCRYPT_PREFER_ENCRYPT,
                accountState.getEncryptionPreference().toString());
        return ArmorUtils.toAsciiArmoredString(accountState.getSecretKey(), header);
    }

    public ListenableFuture<Void> importSecretKey(final String message, final String passphrase) {
        final ByteArrayInputStream encryptedStream =
                new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        final ConsumerOptions consumerOptions =
                new ConsumerOptions().addDecryptionPassphrase(Passphrase.fromPassword(passphrase));
        final ListenableFuture<DecryptionStream> streamFuture =
                Futures.submit(
                        () ->
                                PGPainless.decryptAndOrVerify()
                                        .onInputStream(encryptedStream)
                                        .withOptions(consumerOptions),
                        CRYPTO_EXECUTOR);
        return Futures.transformAsync(streamFuture, this::importSecretKey, CRYPTO_EXECUTOR);
    }

    @NonNull
    private ListenableFuture<Void> importSecretKey(final DecryptionStream decryptionStream)
            throws IOException {
        final ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();
        ByteStreams.copy(decryptionStream, plaintextStream);
        final byte[] plaintext = plaintextStream.toByteArray();
        final PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(plaintext);
        final Optional<EncryptionPreference> preferenceOptional =
                getEncryptionPreference(plaintext);
        if (PGPKeyRings.isSuitableForEncryption(PGPainless.extractCertificate(secretKey))) {
            return importSecretKey(
                    secretKey, preferenceOptional.or(defaultSettings.getEncryptionPreference()));
        } else {
            return Futures.immediateFailedFuture(
                    new IllegalArgumentException("PublicKey is not suitable for encryption"));
        }
    }

    private Optional<EncryptionPreference> getEncryptionPreference(final byte[] asciiArmor)
            throws IOException {
        final ArmoredInputStream armoredInputStream =
                ArmoredInputStreamFactory.get(new ByteArrayInputStream(asciiArmor));
        final List<String> values =
                ArmorUtils.getArmorHeaderValues(
                        armoredInputStream, Headers.AUTOCRYPT_PREFER_ENCRYPT);
        if (values.size() > 0) {
            final String value = values.get(0);
            return Optional.of(EncryptionPreference.of(value));
        } else {
            return Optional.absent();
        }
    }

    private ListenableFuture<Void> importSecretKey(
            final PGPSecretKeyRing secretKeyRing, final EncryptionPreference preference) {
        return Futures.submit(
                () -> {
                    final AccountState accountState =
                            ImmutableAccountState.builder()
                                    .secretKey(PGPKeyRings.keyData(secretKeyRing))
                                    .encryptionPreference(preference)
                                    .isEnabled(defaultSettings.isEnabled())
                                    .build();
                    storeAccountState(accountState);
                    return null;
                },
                ioExecutorService);
    }
}
