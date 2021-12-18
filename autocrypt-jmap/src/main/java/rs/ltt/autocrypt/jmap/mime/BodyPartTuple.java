package rs.ltt.autocrypt.jmap.mime;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import rs.ltt.jmap.common.entity.EmailBodyPart;
import rs.ltt.jmap.common.entity.EmailBodyValue;

public class BodyPartTuple {

    public final EmailBodyPart emailBodyPart;
    public final InputStream inputStream;

    private BodyPartTuple(final EmailBodyPart emailBodyPart, final InputStream inputStream) {
        this.emailBodyPart = emailBodyPart;
        this.inputStream = inputStream;
    }

    public static BodyPartTuple of(
            final EmailBodyPart emailBodyPart, final EmailBodyValue emailBodyValue) {
        return of(emailBodyPart, emailBodyValue.getValue());
    }

    public static BodyPartTuple of(final EmailBodyPart emailBodyPart, final String body) {
        return of(emailBodyPart, new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
    }

    public static BodyPartTuple of(
            final EmailBodyPart emailBodyPart, final InputStream inputStream) {
        return new BodyPartTuple(emailBodyPart, inputStream);
    }
}
