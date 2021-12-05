package rs.ltt.autocrypt.client.header;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

public class AutocryptHeaderTest {

    @Test
    public void testAliceMutual() {
        final String example =
                "addr=alice@autocrypt.example; prefer-encrypt=mutual; keydata=\n"
                    + " mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/Ub7O1u120F2F\n"
                    + " saWNlQGF1dG9jcnlwdC5leGFtcGxliJYEExYIAD4WIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXE\n"
                    + " cE6QIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDyMVUMT0fjjkqLAP9frlijw\n"
                    + " BJvA+HFnqCZcYIVxlyXzS5Gi5gMTpp37K73jgD/VbKYhkwk9iu689OYH4K7q7LbmdeaJ+RX88Y/\n"
                    + " ad9hZwy4OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3sE9+\n"
                    + " eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIbDAAKCRDyMVUMT0\n"
                    + " fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn0QEA22Kr7VkCjeAEC08VSTeV+\n"
                    + " QFsmz55/lntWkwYWhmvOgE=";
        final AutocryptHeader autocryptHeader = AutocryptHeader.parse(example);
        Assertions.assertEquals("alice@autocrypt.example", autocryptHeader.getAddress());
        Assertions.assertEquals(
                EncryptionPreference.MUTUAL, autocryptHeader.getEncryptionPreference());
    }

    @Test
    public void testUnknownKey() {
        final IllegalArgumentException exception =
                Assertions.assertThrows(
                        IllegalArgumentException.class,
                        () -> AutocryptHeader.parse("foo=bar; addr=test@example.com"));
        Assertions.assertEquals("Unexpected attribute foo", exception.getMessage());
    }

    @Test
    public void testIgnoredKey() {
        final AutocryptHeader autocryptHeader =
                AutocryptHeader.parse("_ignored=bar; addr=test@example.com; keydata=AAo=");
        Assertions.assertEquals("test@example.com", autocryptHeader.getAddress());
    }

    @Test
    public void parseAndFormat() {
        final String value = "addr=test@example.com; keydata=AAo=";
        final AutocryptHeader autocryptHeader = AutocryptHeader.parse(value);
        Assertions.assertEquals(value, autocryptHeader.toHeaderValue());
    }

    @Test
    public void semicolonInEmail() {
        final AutocryptHeader autocryptHeader =
                AutocryptHeader.parse(
                        "addr=\";test;\"@example.com; prefer-encrypt=nopreference; keydata=AAo=");
        Assertions.assertEquals("\";test;\"@example.com", autocryptHeader.getAddress());
        Assertions.assertEquals(
                EncryptionPreference.NO_PREFERENCE, autocryptHeader.getEncryptionPreference());
    }

    @Test
    public void missingKeyName() {
        final IllegalArgumentException exception =
                Assertions.assertThrows(
                        IllegalArgumentException.class, () -> AutocryptHeader.parse("=value"));
        Assertions.assertEquals("Attribute name can not be empty", exception.getMessage());
    }

    @Test
    public void unexpectedEnd() {
        final IllegalArgumentException exception =
                Assertions.assertThrows(
                        IllegalArgumentException.class, () -> AutocryptHeader.parse("key=\"value"));
        Assertions.assertEquals("Unexpected end (quotation not closed)", exception.getMessage());
    }

    @Test
    public void invalidPreference() {
        final IllegalArgumentException exception =
                Assertions.assertThrows(
                        IllegalArgumentException.class,
                        () -> AutocryptHeader.parse("prefer-encrypt=invalid"));
        Assertions.assertEquals(
                "invalid is not a known encryption preference", exception.getMessage());
    }

    @Test
    public void emptyKeyData() {
        final IllegalArgumentException exception =
                Assertions.assertThrows(
                        IllegalArgumentException.class,
                        () -> AutocryptHeader.parse("addr=test@example.com; keydata=;"));
        Assertions.assertEquals("Value for keydata can not be empty", exception.getMessage());
    }

    @Test
    public void createFromKey()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        final PGPSecretKeyRing secretKey =
                PGPainless.generateKeyRing().modernKeyRing("Test Test <test@example.com>", null);
        final AutocryptHeader header =
                AutocryptHeader.of(secretKey, EncryptionPreference.NO_PREFERENCE);
        final String headerValue = header.toHeaderValue();
        assertThat(headerValue, startsWith("addr=test@example.com;"));
        assertThat(headerValue, containsString("prefer-encrypt=nopreference"));
    }
}
