package rs.ltt.autocrypt.jmap;

import com.google.common.collect.Iterables;
import com.google.common.io.BaseEncoding;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import rs.ltt.autocrypt.client.PGPKeyRings;
import rs.ltt.autocrypt.client.header.EncryptionPreference;
import rs.ltt.autocrypt.client.storage.AccountState;
import rs.ltt.autocrypt.client.storage.ImmutableAccountState;
import rs.ltt.autocrypt.client.storage.PeerState;
import rs.ltt.autocrypt.client.storage.Storage;

public class FixedKeyStorage implements Storage {

    private static final Pattern ANGLE_ADDR_PATTERN = Pattern.compile("<(.+?)>");

    public static final PGPSecretKeyRing SECRET_KEY_ALICE =
            PGPKeyRings.readSecretKeyRing(
                    BaseEncoding.base64()
                            .decode(
                                    "lFgEYb8fshYJKwYBBAHaRw8BAQdAIN5/teAN+st+PVvO5GFftDDZslpgQMM6iVJQi9jdyj8AAQCDs7dwuSg3LTvvDnXM2igHDd8TtrmhrU+oBaXHZqPfLQ9etBM8YWxpY2VAZXhhbXBsZS5jb20+iI8EExYKAEEFAmG/H7IJkCUzj2vRMR8fFqEE7Vr/ildDA+YjtErSJTOPa9ExHx8CngECmwMFlgIDAQAEiwkIBwWVCgkICwKZAQAAQWABAI/3UZLVT/i97COvTlzqYJikfkoE7nFfDTjFsvBSYMQ6AP9WMikngzNWu4KH0u9KPpk8UxU7H1FHlU9RFghN6S7PBJxdBGG/H7ISCisGAQQBl1UBBQEBB0CfQIiQoRZsPDwC27mhmtFU/iWjKh+aWVOkp7+sT6KFPAMBCAcAAP9ogyDigtalAUlKeZYOSJJsC4WMomUI7NgykRp0Z2MZMA4ziHUEGBYKAB0FAmG/H7ICngECmwwFlgIDAQAEiwkIBwWVCgkICwAKCRAlM49r0TEfH5zSAPkBMgvuriT0V0jQMk21dmilLke4Uwhq31LwpqwtVYoapAD/Sf9SgTP/zJAQ01aE57bDziRU9oBsC6Pi5IfgXbuK4Aw="));
    public static final PGPSecretKeyRing SECRET_KEY_BOB =
            PGPKeyRings.readSecretKeyRing(
                    BaseEncoding.base64()
                            .decode(
                                    "lFgEYb8gJhYJKwYBBAHaRw8BAQdAOuaJabvwRoAXH1j7ErsCOXZBGbMZhxP8aEzN2rRebJ8AAQDTjjPp82rH0g7wbUpDdOi4zh2LU1dm5c7SB4cMDXXRbRDltBE8Ym9iQGV4YW1wbGUuY29tPoiPBBMWCgBBBQJhvyAmCZDg+gXkZrlr9BahBC6daxGeifCIPdzdSOD6BeRmuWv0Ap4BApsDBZYCAwEABIsJCAcFlQoJCAsCmQEAAN+7AQDbTpClvUpB5r8DhpqEK9Y3f4hWvFnWCkI175gQyRM9qAEAyp7SzuA7og23/D7AY2tcO4sUGA4ODhYW1i1X2mhx4w6cXQRhvyAmEgorBgEEAZdVAQUBAQdAhlNGzvUHR+7IuZKSdbB9tkuv8NiAjg6yookzWFo6ulgDAQgHAAD/evLqw5ympPJppaKu2rERg8oDISH08SVwKbKN2zgPtDgSbIh1BBgWCgAdBQJhvyAmAp4BApsMBZYCAwEABIsJCAcFlQoJCAsACgkQ4PoF5Ga5a/SjKQEAqQgcKwuW6DFExxIDEFJaHqbTLSDzi9JN9vnfbeG2VdIA/jrlommZqJY0WW7cXDpCNaK2kMUNresZPmPdAX99fAUO"));

    private final PGPSecretKeyRing secretKeyRing;
    private final Collection<PGPPublicKeyRing> publicKeyRings;

    public FixedKeyStorage(
            PGPSecretKeyRing secretKeyRing, Collection<PGPPublicKeyRing> publicKeyRings) {
        this.secretKeyRing = secretKeyRing;
        this.publicKeyRings = publicKeyRings == null ? Collections.emptyList() : publicKeyRings;
    }

    @Override
    public boolean updateLastSeen(String address, Instant effectiveDate) {
        throw new IllegalArgumentException("Not implemented");
    }

    @Override
    public void updateAutocrypt(
            String address,
            Instant effectiveDate,
            byte[] publicKey,
            EncryptionPreference preference) {
        throw new IllegalArgumentException("Not implemented");
    }

    @Override
    public boolean updateGossip(String address, Instant effectiveData, byte[] publicKey) {
        throw new IllegalArgumentException("Not implemented");
    }

    @Override
    public PeerState getPeerState(final String address) {
        final PGPPublicKeyRing publicKeyRing =
                Iterables.find(
                        this.publicKeyRings,
                        key -> {
                            final String userId = PGPainless.inspectKeyRing(key).getPrimaryUserId();
                            final Matcher matcher = ANGLE_ADDR_PATTERN.matcher(userId);
                            return matcher.find() && matcher.group(1).equals(address);
                        });
        if (publicKeyRing == null) {
            return null;
        }
        final Instant timestamp = Instant.now();
        return new PeerState() {
            @Override
            public Instant getLastSeen() {
                return timestamp;
            }

            @Override
            public Instant getAutocryptTimestamp() {
                return timestamp;
            }

            @Override
            public Instant getGossipTimestamp() {
                return null;
            }

            @Override
            public byte[] getPublicKey() {
                return PGPKeyRings.keyData(publicKeyRing);
            }

            @Override
            public byte[] getGossipKey() {
                return new byte[0];
            }

            @Override
            public EncryptionPreference getEncryptionPreference() {
                return EncryptionPreference.NO_PREFERENCE;
            }
        };
    }

    @Override
    public AccountState getAccountState(final String userId) {
        if (secretKeyRing == null) {
            return null;
        }
        return ImmutableAccountState.builder()
                .encryptionPreference(EncryptionPreference.NO_PREFERENCE)
                .secretKey(PGPKeyRings.keyData(secretKeyRing))
                .isEnabled(true)
                .build();
    }

    @Override
    public void setAccountState(final String userId, final AccountState accountState) {
        throw new IllegalArgumentException("Not implemented");
    }
}
