package rs.ltt.autocrypt.client.header;

import com.google.common.base.CharMatcher;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AutocryptHeader {

    private static final String KEY_ADDRESS = "addr";
    private static final String KEY_ENCRYPTION_PREFERENCE = "prefer-encrypt";
    private static final String KEY_KEY_DATA = "keydata";

    private final String address;
    private final EncryptionPreference encryptionPreference;
    private final byte[] keyData;

    public static AutocryptHeader parse(final String header) {
        final AutocryptHeaderBuilder builder = new AutocryptHeaderBuilder();
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
}
