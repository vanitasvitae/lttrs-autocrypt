package rs.ltt.autocrypt.client.header;

import com.google.common.base.Charsets;
import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.MultiMap;

public class PassphraseHint {
    public static final PassphraseHint NONE = new PassphraseHint("", Format.UNKNOWN);
    public final String begin;
    public final Format format;

    public PassphraseHint(final String begin, final Format format) {
        this.begin = begin;
        this.format = format;
    }

    public static PassphraseHint of(final String message) {
        final ArmoredInputStream armoredInputStream;
        try {
            armoredInputStream =
                    ArmoredInputStreamFactory.get(
                            new ByteArrayInputStream(message.getBytes(Charsets.UTF_8)));
        } catch (final IOException e) {
            return NONE;
        }
        final List<String> formats =
                ArmorUtils.getArmorHeaderValues(armoredInputStream, Headers.PASSPHRASE_FORMAT);
        final List<String> beginnings =
                ArmorUtils.getArmorHeaderValues(armoredInputStream, Headers.PASSPHRASE_BEGIN);
        if (formats.isEmpty() || beginnings.isEmpty()) {
            return NONE;
        }
        return new PassphraseHint(beginnings.get(0), Format.of(formats.get(0)));
    }

    public MultiMap<String, String> asHeader() {
        final MultiMap<String, String> additionalHeader = new MultiMap<>();
        additionalHeader.put(Headers.PASSPHRASE_FORMAT, "numeric9x4");
        additionalHeader.put(Headers.PASSPHRASE_BEGIN, begin);
        return additionalHeader;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("begin", begin)
                .add("format", format)
                .toString();
    }

    public enum Format {
        NUMERIC9X4,
        UNKNOWN;

        public static Format of(final String value) {
            if (Strings.isNullOrEmpty(value)) {
                return UNKNOWN;
            }
            try {
                return Format.valueOf(value.toUpperCase(Locale.ROOT));
            } catch (final IllegalArgumentException e) {
                return UNKNOWN;
            }
        }

        @Override
        public String toString() {
            return super.toString().toLowerCase(Locale.ROOT);
        }
    }
}
