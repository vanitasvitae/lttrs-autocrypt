package rs.ltt.autocrypt.jmap;

import com.google.common.base.CharMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SetupMessageTest {

    @Test
    public void generatePassphrase() {
        for (int i = 0; i < 1000; ++i) {
            final String passphrase = SetupMessage.generateSetupCode();
            Assertions.assertEquals(36, passphrase.length());
            Assertions.assertTrue(CharMatcher.inRange('0', '9').matchesAllOf(passphrase));
        }
    }
}
