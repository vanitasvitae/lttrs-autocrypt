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

@SuppressWarnings("UnstableApiUsage")
public class EmailContentHandler implements ContentHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailContentHandler.class);

    private static final MediaType TEXT_PLAIN = MediaType.create("text", "plain");
    private static final MediaType TEXT_HTML = MediaType.create("text", "html");
    private static final MediaType MULTIPART_ANY = MediaType.create("multipart", "*");

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
    public void startMessage() {
        pushEmailBodyPart();
    }

    @Override
    public void endMessage() throws MimeException {
        pollEmailBodyPart();
        final int pendingBodyPartBuilders = emailBodyPartBuilders.size();
        if (pendingBodyPartBuilders > 0) {
            throw new MimeException(pendingBodyPartBuilders + "pending bodyPartBuilders");
        }
    }

    @Override
    public void startBodyPart() {
        pushEmailBodyPart();
    }

    @Override
    public void endBodyPart() {
        pollEmailBodyPart();
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
                break;
            default:
                LOGGER.debug("Encountered unknown header {}", name);
                break;
        }
    }

    @Override
    public void endHeader() {}

    @Override
    public void preamble(InputStream inputStream) {}

    @Override
    public void epilogue(InputStream inputStream) {}

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
        if (alternatives != null && !alternatives.isEmpty()) {
            emailBuilder.textBody(pickAlternative(alternatives, TEXT_PLAIN));
        }
        this.multipartDepth--;
    }

    private static EmailBodyPart pickAlternative(
            List<EmailBodyPart> alternatives, final MediaType preferredMediaType) {
        final Optional<EmailBodyPart> textVariant =
                Iterables.tryFind(
                        alternatives,
                        emailBodyPart -> {
                            final MediaType mediaType = emailBodyPart.getMediaType();
                            return mediaType != null && mediaType.is(preferredMediaType);
                        });
        if (textVariant.isPresent()) {
            return textVariant.get();
        } else {
            return Iterables.getFirst(alternatives, null);
        }
    }

    @Override
    public void body(BodyDescriptor bodyDescriptor, InputStream inputStream) throws IOException {
        final EmailBodyPart.EmailBodyPartBuilder bodyPartBuilder =
                this.emailBodyPartBuilders.getLast();
        final EmailBodyPart emailBodyPart = bodyPartBuilder.build();
        final MediaType mediaType = emailBodyPart.getMediaType();
        final long bytesCopied;
        if (mediaType != null && (mediaType.is(TEXT_PLAIN) || mediaType.is(TEXT_HTML))) {
            final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            bytesCopied = ByteStreams.copy(inputStream, byteArrayOutputStream);
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
            bytesCopied =
                    this.attachmentRetriever.onAttachmentRetrieved(emailBodyPart, inputStream);
        }
        bodyPartBuilder.size(bytesCopied);
    }

    @Override
    public void raw(InputStream inputStream) {}

    private void pollEmailBodyPart() {
        final EmailBodyPart.EmailBodyPartBuilder builder = this.emailBodyPartBuilders.pollLast();
        final EmailBodyPart emailBodyPart = builder.build();
        final MediaType mediaType = emailBodyPart.getMediaType();
        if (mediaType != null && mediaType.is(MULTIPART_ANY)) {
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

    private void pushEmailBodyPart() {
        final EmailBodyPart.EmailBodyPartBuilder builder = EmailBodyPart.builder();
        this.emailBodyPartBuilders.add(builder);
        this.partId++;
        builder.partId(String.valueOf(this.partId));
        final String hash =
                Hashing.sha256()
                        .newHasher()
                        .putInt(this.partId)
                        .putBytes(blobIdSeed)
                        .hash()
                        .toString();
        builder.blobId(String.format("PTA-%s-%d", hash, partId));
    }

    public Email buildEmail() {
        return this.emailBuilder.build();
    }
}
