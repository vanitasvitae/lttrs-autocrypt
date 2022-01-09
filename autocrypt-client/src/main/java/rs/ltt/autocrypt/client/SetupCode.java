package rs.ltt.autocrypt.client;

import com.google.common.base.CharMatcher;
import com.google.common.base.Preconditions;

public class SetupCode {

    public static final int LENGTH = 36;

    private SetupCode() {}

    public static void checkArgument(final String passphrase) {
        Preconditions.checkArgument(
                CharMatcher.inRange('0', '9').matchesAllOf(passphrase),
                "Setup code must consist of " + LENGTH + " numeric characters");
        Preconditions.checkArgument(
                passphrase.length() == LENGTH,
                "Setup code must consist of " + LENGTH + " numeric characters");
    }

    public static boolean isValid(final String passphrase) {
        return passphrase.length() == LENGTH
                && CharMatcher.inRange('0', '9').matchesAllOf(passphrase);
    }
}
