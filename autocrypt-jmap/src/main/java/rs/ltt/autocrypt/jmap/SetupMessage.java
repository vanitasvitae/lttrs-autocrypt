package rs.ltt.autocrypt.jmap;

import com.google.common.base.Strings;
import com.google.common.net.MediaType;
import java.math.BigInteger;
import java.security.SecureRandom;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailBodyPart;
import rs.ltt.jmap.common.entity.EmailBodyValue;

public class SetupMessage {

    public static final MediaType AUTOCRYPT_SETUP =
            MediaType.create("application", "autocrypt-setup");

    private static final String FILENAME = "autocrypt-setup-message.asc";

    private static final String SUBJECT = "Autocrypt Setup Message";

    private static final String BODY =
            "This message contains all information to transfer your Autocrypt\n"
                    + "settings along with your secret key securely from your original\n"
                    + "device.\n"
                    + "\n"
                    + "To set up your new device for Autocrypt, please follow the\n"
                    + "instructions that should be presented by your new device.\n"
                    + "\n"
                    + "You can keep this message and use it as a backup for your secret\n"
                    + "key. If you want to do this, you should write down the Setup Code\n"
                    + "and store it securely.";

    public static Email ofAttachment(final String message) {
        final EmailBodyValue bodyValue = EmailBodyValue.builder().value(BODY).build();
        final EmailBodyValue attachmentValue = EmailBodyValue.builder().value(message).build();
        final EmailBodyPart body =
                EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).partId("1").build();
        final EmailBodyPart attachment =
                EmailBodyPart.builder()
                        .partId("2")
                        .mediaType(AUTOCRYPT_SETUP)
                        .disposition("attachment")
                        .name(FILENAME)
                        .build();
        return Email.builder()
                .autocryptSetupMessage("v1")
                .subject(SUBJECT)
                .bodyValue("1", bodyValue)
                .bodyValue("2", attachmentValue)
                .textBody(body)
                .attachment(attachment)
                .build();
    }

    public static String generateSetupCode() {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        final BigInteger bigInteger = new BigInteger(1, bytes);
        final String random =
                Strings.padStart(bigInteger.toString(), AutocryptClient.SETUP_CODE_LENGTH, '0');
        return random.substring(0, AutocryptClient.SETUP_CODE_LENGTH);
    }
}
