package rs.ltt.autocrypt.jmap;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.common.net.MediaType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.dom.MessageWriter;
import org.apache.james.mime4j.message.BodyPartBuilder;
import org.apache.james.mime4j.message.DefaultMessageWriter;
import org.apache.james.mime4j.message.MultipartBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.autocrypt.jmap.mime.MimeTransformer;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailBodyPart;

public class MimeTransformerTest {

    public static final byte[] BLACK_SQUARE_PNG =
            BaseEncoding.base64()
                    .decode(
                            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAACXBIWXMAAC4jAAAuIwF4pT92AAAADElEQVQI12NgYGAAAAAEAAEnNCcKAAAAAElFTkSuQmCC");

    @Test
    public void emptyBodyParts() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> {
                    MimeTransformer.transform(Collections.emptyList());
                });
    }

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

    @Test
    public void emailFromMixedAndAlternative() throws IOException, MimeException {
        final Message.Builder builder = Message.Builder.of();
        final MultipartBuilder mixedMultipartBuilder = MultipartBuilder.create("mixed");
        final MultipartBuilder alternativeMultipartBuilder = MultipartBuilder.create("alternative");
        alternativeMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody("I'm the plain variant", "plain", StandardCharsets.UTF_8)
                        .build());
        alternativeMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody("<h1>I'm the html variant<h1>", "html", StandardCharsets.UTF_8)
                        .build());
        mixedMultipartBuilder.addBodyPart(
                BodyPartBuilder.create().setBody(alternativeMultipartBuilder.build()));
        mixedMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody(BLACK_SQUARE_PNG, "image/png")
                        .setContentTransferEncoding("base64")
                        .setContentDisposition("attachment", "black_square.png"));
        builder.setBody(mixedMultipartBuilder);
        final Message message = builder.build();
        final MessageWriter messageWriter = new DefaultMessageWriter();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        messageWriter.writeMessage(message, byteArrayOutputStream);
        final ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        final List<byte[]> attachments = new ArrayList<>();
        final Email email =
                MimeTransformer.transform(
                        byteArrayInputStream,
                        "test",
                        (attachment, inputStream) -> {
                            final ByteArrayOutputStream attachmentOutputStream =
                                    new ByteArrayOutputStream();
                            ByteStreams.copy(inputStream, attachmentOutputStream);
                            attachments.add(attachmentOutputStream.toByteArray());
                        });
        Assertions.assertEquals(1, attachments.size());
        Assertions.assertEquals(1, email.getAttachments().size());
        Assertions.assertEquals(1, email.getTextBody().size());
    }

    @Test
    public void emailFromMAlternative() throws IOException, MimeException {
        final Message.Builder builder = Message.Builder.of();
        final MultipartBuilder alternativeMultipartBuilder = MultipartBuilder.create("alternative");
        alternativeMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody("I'm the plain variant", "plain", StandardCharsets.UTF_8)
                        .build());
        alternativeMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody("<h1>I'm the html variant<h1>", "html", StandardCharsets.UTF_8)
                        .build());
        builder.setBody(alternativeMultipartBuilder);
        final Message message = builder.build();
        final MessageWriter messageWriter = new DefaultMessageWriter();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        messageWriter.writeMessage(message, byteArrayOutputStream);
        final ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        final List<byte[]> attachments = new ArrayList<>();
        final Email email =
                MimeTransformer.transform(
                        byteArrayInputStream,
                        "test",
                        (attachment, inputStream) -> {
                            final ByteArrayOutputStream attachmentOutputStream =
                                    new ByteArrayOutputStream();
                            ByteStreams.copy(inputStream, attachmentOutputStream);
                            attachments.add(attachmentOutputStream.toByteArray());
                        });
        Assertions.assertEquals(0, attachments.size());
        Assertions.assertEquals(0, email.getAttachments().size());
        Assertions.assertEquals(1, email.getTextBody().size());
    }
}
