package rs.ltt.autocrypt.jmap.mime;

import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.Iterables;
import com.google.common.net.MediaType;
import java.io.*;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.apache.james.mime4j.Charsets;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.dom.*;
import org.apache.james.mime4j.internal.AbstractEntityBuilder;
import org.apache.james.mime4j.message.BodyPart;
import org.apache.james.mime4j.message.BodyPartBuilder;
import org.apache.james.mime4j.message.DefaultMessageWriter;
import org.apache.james.mime4j.message.MultipartBuilder;
import org.apache.james.mime4j.parser.MimeStreamParser;
import org.apache.james.mime4j.stream.MimeConfig;
import org.apache.james.mime4j.stream.NameValuePair;
import org.apache.james.mime4j.stream.RawField;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.Headers;
import rs.ltt.autocrypt.client.state.GossipRetriever;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailBodyPart;

public class MimeTransformer {

    public static void transform(
            final Collection<BodyPartTuple> bodyPartTuples, final OutputStream outputStream)
            throws IOException {
        transform(bodyPartTuples, Collections.emptyList(), outputStream);
    }

    public static void transform(
            final Collection<BodyPartTuple> bodyPartTuples,
            final List<AutocryptHeader> gossipHeader,
            final OutputStream outputStream)
            throws IOException {
        final MessageWriter messageWriter = new DefaultMessageWriter();
        final Message message = transform(bodyPartTuples, gossipHeader);
        messageWriter.writeMessage(message, outputStream);
    }

    public static Message transform(
            final Collection<BodyPartTuple> bodyPartTuples,
            final List<AutocryptHeader> gossipHeader) {
        if (bodyPartTuples.isEmpty()) {
            throw new IllegalArgumentException("Unable to create message with no body parts");
        }
        final Message.Builder builder = Message.Builder.of();
        for (final AutocryptHeader autocryptHeader : gossipHeader) {
            if (autocryptHeader.getEncryptionPreference() != null) {
                throw new IllegalArgumentException(
                        "Gossip Headers SHOULD not include an encryption preference");
            }
            builder.addField(
                    new RawField(Headers.AUTOCRYPT_GOSSIP, autocryptHeader.toHeaderValue()));
        }
        if (bodyPartTuples.size() == 1) {
            final BodyPartTuple bodyPartTuple =
                    Objects.requireNonNull(Iterables.getOnlyElement(bodyPartTuples));
            build(builder, bodyPartTuple);
        } else {
            final MultipartBuilder multipartBuilder = MultipartBuilder.create("mixed");
            for (final BodyPartTuple bodyPartTuple : bodyPartTuples) {
                multipartBuilder.addBodyPart(bodyPart(bodyPartTuple));
            }
            builder.setBody(multipartBuilder.build());
        }
        return builder.build();
    }

    private static void build(AbstractEntityBuilder builder, final BodyPartTuple bodyPartTuple) {
        final EmailBodyPart emailBodyPart = bodyPartTuple.emailBodyPart;
        final MediaType mediaType = emailBodyPart.getMediaType();
        final String contentType = mediaType.withoutParameters().toString();
        if (mediaType.is(MediaType.PLAIN_TEXT_UTF_8)) {
            builder.setContentTransferEncoding("quoted-printable");
            builder.setBody(textBody(bodyPartTuple));
        } else {
            builder.setContentTransferEncoding("base64");
            builder.setBody(binaryBody(bodyPartTuple.inputStream));
        }
        builder.setContentType(contentType, nameValuePairs(mediaType.parameters()));
        final String name = emailBodyPart.getName();
        if (name != null) {
            final String disposition =
                    emailBodyPart.getDisposition() == null
                            ? "attachment"
                            : emailBodyPart.getDisposition();
            builder.setContentDisposition(disposition, name);
        } else if (emailBodyPart.getDisposition() != null) {
            builder.setContentDisposition(emailBodyPart.getDisposition());
        }
    }

    private static BodyPart bodyPart(final BodyPartTuple bodyPartTuple) {
        final BodyPartBuilder builder = BodyPartBuilder.create();
        build(builder, bodyPartTuple);
        return builder.build();
    }

    private static SingleBody textBody(final BodyPartTuple bodyPartTuple) {
        return new TextBody() {
            @Override
            public String getMimeCharset() {
                return Charsets.UTF_8.name();
            }

            @Override
            public Charset getCharset() {
                return Charsets.UTF_8;
            }

            @Override
            public Reader getReader() {
                return new InputStreamReader(bodyPartTuple.inputStream);
            }

            @Override
            public InputStream getInputStream() {
                return bodyPartTuple.inputStream;
            }
        };
    }

    private static BinaryBody binaryBody(final InputStream inputStream) {
        return new BinaryBody() {
            @Override
            public InputStream getInputStream() {
                return inputStream;
            }
        };
    }

    private static NameValuePair[] nameValuePairs(
            final ImmutableListMultimap<String, String> parameters) {
        return Collections2.transform(
                        parameters.entries(), e -> new NameValuePair(e.getKey(), e.getValue()))
                .toArray(new NameValuePair[0]);
    }

    public static Message transform(final Collection<BodyPartTuple> bodyPartTuples) {
        return transform(bodyPartTuples, Collections.emptyList());
    }

    public static Email transform(
            final InputStream inputStream,
            final String blobId,
            final AttachmentRetriever attachmentRetriever,
            final GossipRetriever gossipRetriever)
            throws MimeException, IOException {
        final MimeConfig mimeConfig = new MimeConfig.Builder().build();
        final MimeStreamParser mimeStreamParser = new MimeStreamParser(mimeConfig);
        mimeStreamParser.setContentDecoding(true);
        final EmailContentHandler emailContentHandler =
                new EmailContentHandler(blobId, attachmentRetriever, gossipRetriever);
        mimeStreamParser.setContentHandler(emailContentHandler);
        mimeStreamParser.parse(inputStream);
        return emailContentHandler.buildEmail();
    }
}
