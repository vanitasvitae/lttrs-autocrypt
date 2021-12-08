package rs.ltt.autocrypt.client.header;

import com.google.common.base.CharMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.immutables.value.Value;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;
import rs.ltt.autocrypt.client.PGPPublicKeyRings;

@Value.Immutable
public abstract class AutocryptHeader {

    private static final String KEY_ADDRESS = "addr";
    private static final String KEY_ENCRYPTION_PREFERENCE = "prefer-encrypt";
    private static final String KEY_KEY_DATA = "keydata";

    private static final Pattern ANGLE_ADDR_PATTERN = Pattern.compile("<(.+?)>");

    public static AutocryptHeader parse(final String header) {
        final ImmutableAutocryptHeader.Builder builder = ImmutableAutocryptHeader.builder();
        for (final Attribute attribute : Attribute.parse(header)) {
            final String key = attribute.getKey();
            final String value = attribute.getValue();
            if (KEY_ADDRESS.equals(key)) {
                builder.address(attribute.getValue());
            } else if (KEY_ENCRYPTION_PREFERENCE.equals(key)) {
                builder.encryptionPreference(EncryptionPreference.of(value));
            } else if (KEY_KEY_DATA.equals(key)) {
                if (Strings.isNullOrEmpty(value)) {
                    throw new IllegalArgumentException("Value for keydata can not be empty");
                }
                builder.keyData(
                        BaseEncoding.base64().decode(CharMatcher.whitespace().removeFrom(value)));
            } else if (key.charAt(0) != '_') {
                throw new IllegalArgumentException(String.format("Unexpected attribute %s", key));
            }
        }
        return builder.build();
    }

    public static AutocryptHeader of(
            final String from,
            final PGPSecretKeyRing secretKeyRing,
            final EncryptionPreference preference) {
        return of(from, KeyRingUtils.publicKeyRingFrom(secretKeyRing), preference);
    }

    public static AutocryptHeader of(
            final String from,
            final PGPPublicKeyRing publicKeyRing,
            final EncryptionPreference preference) {
        return ImmutableAutocryptHeader.builder()
                .address(from)
                .keyData(PGPPublicKeyRings.keyData(publicKeyRing))
                .encryptionPreference(preference)
                .build();
    }

    public static AutocryptHeader of(
            final PGPSecretKeyRing secretKeyRing, final EncryptionPreference preference) {
        return of(KeyRingUtils.publicKeyRingFrom(secretKeyRing), preference);
    }

    public static AutocryptHeader of(
            final PGPPublicKeyRing publicKeyRing, final EncryptionPreference preference) {
        final KeyRingInfo keyInfo = PGPainless.inspectKeyRing(publicKeyRing);
        final String userId = keyInfo.getPrimaryUserId();
        if (Strings.isNullOrEmpty(userId)) {
            throw new IllegalArgumentException("PublicKeyRing does not contain a primary user id");
        }
        final Matcher matcher = ANGLE_ADDR_PATTERN.matcher(userId);
        if (matcher.find()) {
            return of(matcher.group(1), publicKeyRing, preference);
        }
        throw new IllegalArgumentException("UserId does not follow angle-addr convention");
    }

    public String toHeaderValue() {
        return Joiner.on("; ").join(Lists.transform(toAttributes(), Attribute::formatted));
    }

    private List<Attribute> toAttributes() {
        final ImmutableList.Builder<Attribute> attributes = new ImmutableList.Builder<>();
        attributes.add(new Attribute(KEY_ADDRESS, getAddress()));
        final EncryptionPreference encryptionPreference = getEncryptionPreference();
        if (encryptionPreference != null) {
            attributes.add(
                    new Attribute(KEY_ENCRYPTION_PREFERENCE, encryptionPreference.toString()));
        }
        final byte[] keyData = getKeyData();
        if (keyData != null) {
            attributes.add(new Attribute(KEY_KEY_DATA, BaseEncoding.base64().encode(keyData)));
        }
        return attributes.build();
    }

    public abstract String getAddress();

    public abstract byte[] getKeyData();

    @Nullable
    public abstract EncryptionPreference getEncryptionPreference();
}
