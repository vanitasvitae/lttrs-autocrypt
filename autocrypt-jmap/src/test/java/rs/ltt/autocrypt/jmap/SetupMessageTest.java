package rs.ltt.autocrypt.jmap;

import com.google.common.base.CharMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SetupMessageTest {

    @Test
    public void generatePassphrase() {
        final String passphrase = SetupMessage.generateSetupCode();
        Assertions.assertEquals(36, passphrase.length());
        Assertions.assertTrue(CharMatcher.inRange('0', '9').matchesAllOf(passphrase));
    }
}
