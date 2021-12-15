package rs.ltt.autocrypt.jmap;

import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailAddress;

public class AutocryptClientTest {

    @Test
    public void missingUserId() {
        Assertions.assertThrows(
                IllegalStateException.class, () -> AutocryptClient.builder().build());
    }

    @Test
    public void injectIntoEmail() throws ExecutionException, InterruptedException {
        final AutocryptClient autocryptClient =
                AutocryptClient.builder().userId("alice@example.com").build();
        final Email email =
                Email.builder()
                        .subject("This is a Test")
                        .from(EmailAddress.builder().email("alice@example.com").build())
                        .to(EmailAddress.builder().email("bob@example.com").build())
                        .build();
        final Email result = autocryptClient.injectAutocryptHeader(email).get();
        final List<String> autocryptHeaders = result.getAutocrypt();
        Assertions.assertEquals(1, autocryptHeaders.size());
    }
}
