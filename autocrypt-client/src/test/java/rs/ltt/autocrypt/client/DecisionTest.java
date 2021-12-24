package rs.ltt.autocrypt.client;

import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DecisionTest {

    @Test
    public void oneIsDisable() {
        Assertions.assertEquals(
                Decision.DISABLE,
                Decision.combine(
                        Arrays.asList(Decision.AVAILABLE, Decision.DISCOURAGE, Decision.DISABLE)));
    }

    @Test
    public void oneIsDiscourage() {
        Assertions.assertEquals(
                Decision.DISCOURAGE,
                Decision.combine(
                        Arrays.asList(Decision.AVAILABLE, Decision.DISCOURAGE, Decision.ENCRYPT)));
    }

    @Test
    public void allAreEncrypt() {
        Assertions.assertEquals(
                Decision.ENCRYPT,
                Decision.combine(
                        Arrays.asList(Decision.ENCRYPT, Decision.ENCRYPT, Decision.ENCRYPT)));
    }

    @Test
    public void encryptAndAvailable() {
        Assertions.assertEquals(
                Decision.AVAILABLE,
                Decision.combine(
                        Arrays.asList(Decision.ENCRYPT, Decision.ENCRYPT, Decision.AVAILABLE)));
    }

    @Test
    public void none() {
        Assertions.assertEquals(Decision.DISABLE, Decision.combine(Collections.emptyList()));
    }
}
