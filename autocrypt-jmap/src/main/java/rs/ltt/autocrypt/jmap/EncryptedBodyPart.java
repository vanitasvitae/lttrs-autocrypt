package rs.ltt.autocrypt.jmap;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;
import com.google.common.net.MediaType;
import java.util.List;
import java.util.Map;
import rs.ltt.jmap.common.entity.*;

@SuppressWarnings("UnstableApiUsage")
public class EncryptedBodyPart {

    public static final MediaType APPLICATION_PGP_ENCRYPTED =
            MediaType.create("application", "pgp-encrypted");
    public static final MediaType MULTIPART_ENCRYPTED = MediaType.create("multipart", "encrypted");

    private static final String VERSION_ONE = "Version 1";
    private static final String VERSION_BODY_PART_ID = "version";
    public static final Map<String, EmailBodyValue> BODY_VALUES =
            ImmutableMap.of(
                    VERSION_BODY_PART_ID, EmailBodyValue.builder().value(VERSION_ONE).build());
    private static final String FILENAME = "encrypted.asc";

    public static Email.EmailBuilder insertEncryptedBlob(
            final Email.EmailBuilder emailBuilder, final BinaryData binaryData) {
        return emailBuilder.bodyStructure(of(binaryData)).bodyValues(BODY_VALUES);
    }

    public static EmailBodyPart of(final BinaryData binaryData) {
        final EmailBodyPart versionBodyPart =
                EmailBodyPart.builder()
                        .partId(VERSION_BODY_PART_ID)
                        .mediaType(APPLICATION_PGP_ENCRYPTED)
                        .build();
        final EmailBodyPart encryptedBodyPart =
                EmailBodyPart.builder()
                        .blobId(binaryData.getBlobId())
                        .disposition("inline")
                        .name(FILENAME)
                        .mediaType(MediaType.OCTET_STREAM)
                        .build();
        return EmailBodyPart.builder()
                .mediaType(MULTIPART_ENCRYPTED)
                .subPart(versionBodyPart)
                .subPart(encryptedBodyPart)
                .build();
    }

    public static Optional<Downloadable> findEncryptedBodyPart(final Email email) {
        final EmailBodyPart bodyStructure = email.getBodyStructure();
        if (bodyStructure == null) {
            throw new IllegalArgumentException(
                    "Email did not contain BodyStructure. This needs to be requested explicitly");
        }
        if (bodyStructure.getMediaType().is(MULTIPART_ENCRYPTED)) {
            final List<EmailBodyPart> subParts = bodyStructure.getSubParts();
            if (subParts == null || subParts.size() != 2) {
                return Optional.absent();
            }
            final MediaType firstMediaType = subParts.get(0).getMediaType();
            final MediaType secondMediaType = subParts.get(1).getMediaType();
            if (firstMediaType != null
                    && firstMediaType.is(APPLICATION_PGP_ENCRYPTED)
                    && secondMediaType != null
                    && secondMediaType.is(MediaType.OCTET_STREAM)) {
                return Optional.of(subParts.get(1));
            }
        }
        return Optional.absent();
    }

    public static Downloadable getDownloadable(final String blobId) {
        return new Downloadable() {
            @Override
            public String getName() {
                return FILENAME;
            }

            @Override
            public String getBlobId() {
                return blobId;
            }

            @Override
            public String getType() {
                return MediaType.OCTET_STREAM.toString();
            }

            @Override
            public Long getSize() {
                return null;
            }
        };
    }
}
