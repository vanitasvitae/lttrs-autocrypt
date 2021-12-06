package rs.ltt.autocrypt.client;

import java.net.IDN;
import java.util.Locale;

public final class Addresses {

    private Addresses() {
        throw new IllegalStateException("Do not instantiate me");
    }

    public static String normalize(final String input) {
        final String normalized = input.trim().toLowerCase(Locale.ROOT);
        final int atPosition = normalized.lastIndexOf('@');
        if (atPosition == -1) {
            return normalized;
        }
        final String mailbox = normalized.substring(0, atPosition);
        final String domain = IDN.toASCII(normalized.substring(atPosition + 1));
        return String.format("%s@%s", mailbox, domain);
    }
}
