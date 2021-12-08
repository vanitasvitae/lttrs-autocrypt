package rs.ltt.autocrypt.client;

import java.util.concurrent.ExecutionException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.storage.InMemoryStorage;

public class AutocryptClientTest {

    @Test
    public void automaticSecretKeyGeneration() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient =
                new AutocryptClient(new InMemoryStorage(), "test@example.com");
        final AutocryptHeader autocryptHeader = autocryptClient.getAutocryptHeader().get();

        PGPPublicKeyRing publicKey =
                PGPPublicKeyRings.readPublicKeyRing(autocryptHeader.getKeyData());
        Assertions.assertEquals("test@example.com", autocryptHeader.getAddress());
        Assertions.assertTrue(PGPPublicKeyRings.isSuitableForEncryption(publicKey));
    }
}
