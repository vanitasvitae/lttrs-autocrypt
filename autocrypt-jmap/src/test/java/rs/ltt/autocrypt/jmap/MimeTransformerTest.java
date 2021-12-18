package rs.ltt.autocrypt.jmap;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import com.google.common.net.MediaType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.autocrypt.jmap.mime.MimeTransformer;
import rs.ltt.jmap.common.entity.EmailBodyPart;

public class MimeTransformerTest {

    private static final byte[] BLACK_SQUARE_PNG =
            BaseEncoding.base64()
                    .decode(
                            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAACXBIWXMAAC4jAAAuIwF4pT92AAAADElEQVQI12NgYGAAAAAEAAEnNCcKAAAAAElFTkSuQmCC");

    @Test
    public void simpleText() throws IOException {
        final ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
        final BodyPartTuple textBody =
                BodyPartTuple.of(
                        EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).build(),
                        "Hello World! Schöne Grüße");
        MimeTransformer.transform(ImmutableList.of(textBody), resultOutputStream);
        final String message = new String(resultOutputStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(message, containsString("Hello World! Sch=C3=B6ne Gr=C3=BC=C3=9Fe"));
        assertThat(message, containsString("Content-Transfer-Encoding: quoted-printable"));
    }

    @Test
    public void withAttachment() throws IOException {
        final ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
        final BodyPartTuple textBody =
                BodyPartTuple.of(
                        EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).build(),
                        "Hello World! Schöne Grüße");
        final BodyPartTuple attachment =
                BodyPartTuple.of(
                        EmailBodyPart.builder()
                                .mediaType(MediaType.PNG)
                                .name("blacksquare.png")
                                .disposition("attachment")
                                .build(),
                        new ByteArrayInputStream(BLACK_SQUARE_PNG));
        MimeTransformer.transform(ImmutableList.of(textBody, attachment), resultOutputStream);
        final String message = new String(resultOutputStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(message, containsString("Hello World! Sch=C3=B6ne Gr=C3=BC=C3=9Fe"));
        assertThat(message, containsString("Content-Transfer-Encoding: quoted-printable"));
        assertThat(message, containsString("Content-Type: image/png"));
    }
}
