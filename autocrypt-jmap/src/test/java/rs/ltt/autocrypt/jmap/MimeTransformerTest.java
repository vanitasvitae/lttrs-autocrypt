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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.dom.MessageWriter;
import org.apache.james.mime4j.message.BodyPartBuilder;
import org.apache.james.mime4j.message.DefaultMessageWriter;
import org.apache.james.mime4j.message.MultipartBuilder;
import org.apache.james.mime4j.stream.RawField;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.ImmutableAutocryptHeader;
import rs.ltt.autocrypt.client.state.GossipRetriever;
import rs.ltt.autocrypt.client.state.GossipUpdate;
import rs.ltt.autocrypt.jmap.mime.BodyPartTuple;
import rs.ltt.autocrypt.jmap.mime.MimeTransformer;
import rs.ltt.jmap.common.entity.Attachment;
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
                () -> MimeTransformer.transform(Collections.emptyList()));
    }

    @Test
    public void simpleText() throws IOException {
        final ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
        final BodyPartTuple textBody =
                BodyPartTuple.of(
                        EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).build(),
                        "Hello World! Schöne Grüße");
        MimeTransformer.transform(ImmutableList.of(textBody), resultOutputStream);
        final String message = resultOutputStream.toString(StandardCharsets.UTF_8);
        assertThat(message, containsString("Hello World! Sch=C3=B6ne Gr=C3=BC=C3=9Fe"));
        assertThat(message, containsString("Content-Transfer-Encoding: quoted-printable"));
    }

    @Test
    public void simpleTextAndGossip() throws IOException {
        final ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
        final BodyPartTuple textBody =
                BodyPartTuple.of(
                        EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).build(),
                        "Hello World! Schöne Grüße");
        final List<AutocryptHeader> headers =
                ImmutableList.of(
                        ImmutableAutocryptHeader.builder()
                                .address("alice@example.com")
                                .keyData(new byte[] {0x01, 0x02})
                                .build());
        MimeTransformer.transform(ImmutableList.of(textBody), headers, resultOutputStream);
        final String message = new String(resultOutputStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(
                message, containsString("Autocrypt-Gossip: addr=alice@example.com; keydata=AQI="));
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
                            final long bytes =
                                    ByteStreams.copy(inputStream, attachmentOutputStream);
                            attachments.add(attachmentOutputStream.toByteArray());
                            return bytes;
                        },
                        NoopGossipReceiver.INSTANCE);
        Assertions.assertEquals(1, attachments.size());
        Assertions.assertEquals(1, email.getAttachments().size());
        final Attachment attachment = email.getAttachments().get(0);
        Assertions.assertEquals(BLACK_SQUARE_PNG.length, attachment.getSize());
        Assertions.assertEquals("black_square.png", attachment.getName());
        // blobId is a combination of the PTA prefix (PlainTextAttachment), a hash of the parent
        // blob id, and a partId postfix
        Assertions.assertEquals(
                "PTA-4ff52dd12c768abd4ce7c14da2fd233564a012c4a00ee9ba37fb97c209749230-5",
                attachment.getBlobId());
        Assertions.assertEquals(1, email.getTextBody().size());
    }

    @Test
    public void emailFromAlternative() throws IOException, MimeException {
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
                            final long bytes =
                                    ByteStreams.copy(inputStream, attachmentOutputStream);
                            attachments.add(attachmentOutputStream.toByteArray());
                            return bytes;
                        },
                        NoopGossipReceiver.INSTANCE);
        Assertions.assertEquals(0, attachments.size());
        Assertions.assertEquals(0, email.getAttachments().size());
        Assertions.assertEquals(1, email.getTextBody().size());
    }

    @Test
    public void emailFromSimpleText() throws IOException, MimeException {
        final ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
        final BodyPartTuple textBody =
                BodyPartTuple.of(
                        EmailBodyPart.builder().mediaType(MediaType.PLAIN_TEXT_UTF_8).build(),
                        "Hello World! Schöne Grüße");
        MimeTransformer.transform(ImmutableList.of(textBody), resultOutputStream);
        final ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(resultOutputStream.toByteArray());
        final List<byte[]> attachments = new ArrayList<>();
        final Email email =
                MimeTransformer.transform(
                        byteArrayInputStream,
                        "test",
                        (attachment, inputStream) -> {
                            final ByteArrayOutputStream attachmentOutputStream =
                                    new ByteArrayOutputStream();
                            final long bytes =
                                    ByteStreams.copy(inputStream, attachmentOutputStream);
                            attachments.add(attachmentOutputStream.toByteArray());
                            return bytes;
                        },
                        NoopGossipReceiver.INSTANCE);
        Assertions.assertEquals(0, attachments.size());
        Assertions.assertEquals(0, email.getAttachments().size());
        Assertions.assertEquals(1, email.getTextBody().size());
    }

    @Test
    public void emailWithAutocryptGossip() throws IOException, MimeException {
        final Message.Builder builder = Message.Builder.of();
        builder.addField(new RawField("Autocrypt-Gossip", "addr=alice@example.com; keydata=AAo="));
        builder.addField(new RawField("Autocrypt-Gossip", "addr=parse@failure keydata=AAo="));
        final MultipartBuilder mixedMultipartBuilder = MultipartBuilder.create("mixed");
        mixedMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody("Hello World", "plain", StandardCharsets.UTF_8)
                        .build());
        mixedMultipartBuilder.addBodyPart(
                BodyPartBuilder.create()
                        .setBody(BLACK_SQUARE_PNG, "image/png")
                        .setContentTransferEncoding("base64")
                        .setField(
                                new RawField(
                                        "Autocrypt-Gossip",
                                        "addr=invalid@example.com; keydata=AAo="))
                        .setContentDisposition("attachment", "black_square.png"));
        builder.setBody(mixedMultipartBuilder);
        final Message message = builder.build();
        final MessageWriter messageWriter = new DefaultMessageWriter();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        messageWriter.writeMessage(message, byteArrayOutputStream);
        final ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        final GossipUpdate.Builder gossipBuilder = GossipUpdate.builder(Instant.now());
        final Email email =
                MimeTransformer.transform(
                        byteArrayInputStream,
                        "test",
                        (attachment, inputStream) -> 0L,
                        gossipBuilder);
        Assertions.assertEquals(1, email.getAttachments().size());
        final List<GossipUpdate> gossipUpdates = gossipBuilder.build();
        Assertions.assertEquals(1, gossipUpdates.size());
        Assertions.assertEquals("alice@example.com", gossipUpdates.get(0).getFrom());
    }

    private static class NoopGossipReceiver implements GossipRetriever {

        public static final GossipRetriever INSTANCE = new NoopGossipReceiver();

        @Override
        public void onAutocryptGossipHeader(final AutocryptHeader autocryptHeader) {
            throw new IllegalStateException(
                    NoopGossipReceiver.class.getSimpleName()
                            + " did not expect to receive AutocryptHeader");
        }
    }
}
