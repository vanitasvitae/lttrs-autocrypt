package rs.ltt.autocrypt.client.header;

import com.google.common.base.CharMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import java.util.List;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.immutables.value.Value;

@Value.Immutable
public abstract class AutocryptHeader {

    private static final String KEY_ADDRESS = "addr";
    private static final String KEY_ENCRYPTION_PREFERENCE = "prefer-encrypt";
    private static final String KEY_KEY_DATA = "keydata";

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

    public String toHeaderValue() {
        return Joiner.on("; ").join(Lists.transform(toAttributes(), Attribute::formatted));
    }

    private List<Attribute> toAttributes() {
        final ImmutableList.Builder<Attribute> attributes = new ImmutableList.Builder<>();
        attributes.add(new Attribute(KEY_ADDRESS, getAddress()));
        final byte[] keyData = getKeyData();
        if (keyData != null) {
            attributes.add(new Attribute(KEY_KEY_DATA, BaseEncoding.base64().encode(keyData)));
        }
        final EncryptionPreference encryptionPreference = getEncryptionPreference();
        if (encryptionPreference != null) {
            attributes.add(
                    new Attribute(KEY_ENCRYPTION_PREFERENCE, encryptionPreference.toString()));
        }
        return attributes.build();
    }

    public abstract String getAddress();

    public abstract byte[] getKeyData();

    @Nullable
    public abstract EncryptionPreference getEncryptionPreference();
}
