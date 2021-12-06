package rs.ltt.autocrypt.client;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AddressesTest {

    @Test
    public void idnDomain() {
        Assertions.assertEquals(
                "test@xn--bcher-kva.example", Addresses.normalize("Test@bücher.example"));
    }

    @Test
    public void lowercase() {
        Assertions.assertEquals("test@example.com", Addresses.normalize("Test@example.com"));
    }

    @Test
    public void invalid() {
        Assertions.assertEquals("test@", Addresses.normalize("Test@"));
        Assertions.assertEquals("test", Addresses.normalize("Test"));
        Assertions.assertEquals("@test", Addresses.normalize("@test"));
    }
}
