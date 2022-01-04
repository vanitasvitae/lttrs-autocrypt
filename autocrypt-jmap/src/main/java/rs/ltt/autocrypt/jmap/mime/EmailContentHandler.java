package rs.ltt.autocrypt.jmap.mime;

import com.google.common.base.Optional;
import com.google.common.collect.Iterables;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteStreams;
import com.google.common.net.MediaType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.parser.ContentHandler;
import org.apache.james.mime4j.stream.BodyDescriptor;
import org.apache.james.mime4j.stream.Field;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rs.ltt.autocrypt.client.header.Attribute;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailBodyPart;
import rs.ltt.jmap.common.entity.EmailBodyValue;

public class EmailContentHandler implements ContentHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailContentHandler.class);

    private static final MediaType TEXT_PLAIN = MediaType.create("text", "plain");
    private static final MediaType TEXT_HTML = MediaType.create("text", "html");

    private final Email.EmailBuilder emailBuilder = Email.builder();
    private final AttachmentRetriever attachmentRetriever;
    private final byte[] blobIdSeed;
    private final Map<Integer, List<EmailBodyPart>> alternativesMap = new HashMap<>();
    private final ArrayDeque<EmailBodyPart.EmailBodyPartBuilder> emailBodyPartBuilders =
            new ArrayDeque<>();
    private int partId = 0;
    private int multipartDepth = 0;

    public EmailContentHandler(final String blobId, final AttachmentRetriever attachmentRetriever) {
        this.attachmentRetriever = attachmentRetriever;
        this.blobIdSeed = blobId.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void startMessage() {}

    @Override
    public void endMessage() throws MimeException {
        final int pendingBodyPartBuilders = emailBodyPartBuilders.size();
        if (pendingBodyPartBuilders > 0) {
            throw new MimeException(pendingBodyPartBuilders + "pending bodyPartBuilders");
        }
    }

    @Override
    public void startBodyPart() {
        final EmailBodyPart.EmailBodyPartBuilder builder = EmailBodyPart.builder();
        this.emailBodyPartBuilders.add(builder);
        this.partId++;
        builder.partId(String.valueOf(this.partId));
        builder.blobId(
                Hashing.sha256()
                        .newHasher()
                        .putInt(this.partId)
                        .putBytes(blobIdSeed)
                        .hash()
                        .toString());
    }

    @Override
    public void endBodyPart() {
        final EmailBodyPart.EmailBodyPartBuilder builder = this.emailBodyPartBuilders.pollLast();
        final EmailBodyPart emailBodyPart = builder.build();
        final MediaType mediaType = emailBodyPart.getMediaType();
        if (mediaType != null && "multipart".equals(mediaType.type())) {
            return;
        }
        if (isAttachment(emailBodyPart)) {
            emailBuilder.attachment(emailBodyPart);
            return;
        }
        final List<EmailBodyPart> alternatives = this.alternativesMap.get(this.multipartDepth);
        if (alternatives != null) {
            alternatives.add(emailBodyPart);
        } else {
            emailBuilder.textBody(emailBodyPart);
        }
    }

    private static boolean isAttachment(final EmailBodyPart emailBodyPart) {
        final String disposition = emailBodyPart.getDisposition();
        if ("attachment".equals(disposition)) {
            return true;
        }
        final MediaType mediaType = emailBodyPart.getMediaType();
        return mediaType == null || !isMediaTypeInline(mediaType);
    }

    private static boolean isMediaTypeInline(final MediaType mediaType) {
        return mediaType.is(TEXT_PLAIN)
                || mediaType.is(TEXT_HTML)
                || mediaType.is(MediaType.ANY_IMAGE_TYPE)
                || mediaType.is(MediaType.ANY_AUDIO_TYPE)
                || mediaType.is(MediaType.ANY_VIDEO_TYPE);
    }

    @Override
    public void startHeader() throws MimeException {}

    @Override
    public void field(final Field field) {
        final EmailBodyPart.EmailBodyPartBuilder bodyPartBuilder =
                this.emailBodyPartBuilders.peekLast();
        if (bodyPartBuilder == null) {
            return;
        }
        final String name = field.getNameLowerCase();
        final String value = field.getBody();
        switch (name) {
            case "content-type":
                bodyPartBuilder.mediaType(MediaType.parse(value));
                break;
            case "content-disposition":
                for (final Attribute attribute : Attribute.parse(value)) {
                    final String key = attribute.getKey();
                    if (Arrays.asList("inline", "attachment").contains(key)) {
                        bodyPartBuilder.disposition(key);
                    } else if ("filename".equals(key)) {
                        bodyPartBuilder.name(attribute.getValue());
                    }
                }
        }
    }

    @Override
    public void endHeader() throws MimeException {}

    @Override
    public void preamble(InputStream inputStream) throws MimeException, IOException {}

    @Override
    public void epilogue(InputStream inputStream) throws MimeException, IOException {}

    @Override
    public void startMultipart(final BodyDescriptor bodyDescriptor) {
        this.multipartDepth++;
        if ("multipart/alternative".equals(bodyDescriptor.getMimeType())) {
            this.alternativesMap.put(this.multipartDepth, new ArrayList<>());
        }
    }

    @Override
    public void endMultipart() {
        final List<EmailBodyPart> alternatives = this.alternativesMap.get(this.multipartDepth);
        if (alternatives != null) {
            final Optional<EmailBodyPart> textVariant =
                    Iterables.tryFind(
                            alternatives,
                            emailBodyPart -> {
                                final MediaType mediaType = emailBodyPart.getMediaType();
                                return mediaType != null && mediaType.is(TEXT_PLAIN);
                            });
            if (textVariant.isPresent()) {
                emailBuilder.textBody(textVariant.get());
            } else {
                final EmailBodyPart emailBodyPart = Iterables.getFirst(alternatives, null);
                if (emailBodyPart != null) {
                    emailBuilder.textBody(emailBodyPart);
                }
            }
        }
        this.multipartDepth--;
    }

    @Override
    public void body(BodyDescriptor bodyDescriptor, InputStream inputStream) throws IOException {
        final EmailBodyPart emailBodyPart = this.emailBodyPartBuilders.getLast().build();
        final MediaType mediaType = emailBodyPart.getMediaType();
        if (mediaType != null && (mediaType.is(TEXT_PLAIN) || mediaType.is(TEXT_HTML))) {
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ByteStreams.copy(inputStream, byteArrayOutputStream);
            final String body =
                    new String(byteArrayOutputStream.toByteArray(), StandardCharsets.UTF_8);
            final EmailBodyValue emailBodyValue =
                    EmailBodyValue.builder()
                            .value(body)
                            .isTruncated(false)
                            .isEncodingProblem(false)
                            .build();
            emailBuilder.bodyValue(emailBodyPart.getPartId(), emailBodyValue);
        } else {
            this.attachmentRetriever.onAttachmentRetrieved(emailBodyPart, inputStream);
        }
    }

    @Override
    public void raw(InputStream inputStream) throws MimeException, IOException {}

    public Email buildEmail() {
        return this.emailBuilder.build();
    }
}
