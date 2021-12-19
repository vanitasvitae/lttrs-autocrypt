package rs.ltt.autocrypt.jmap;

import com.google.common.collect.ImmutableMap;
import com.google.common.net.MediaType;
import java.util.Map;
import rs.ltt.jmap.common.entity.Email;
import rs.ltt.jmap.common.entity.EmailBodyPart;
import rs.ltt.jmap.common.entity.EmailBodyValue;
import rs.ltt.jmap.common.entity.Upload;

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
            final Email.EmailBuilder emailBuilder, final Upload upload) {
        return emailBuilder.bodyStructure(of(upload)).bodyValues(BODY_VALUES);
    }

    public static EmailBodyPart of(final Upload upload) {
        final EmailBodyPart versionBodyPart =
                EmailBodyPart.builder()
                        .partId(VERSION_BODY_PART_ID)
                        .mediaType(APPLICATION_PGP_ENCRYPTED)
                        .build();
        final EmailBodyPart encryptedBodyPart =
                EmailBodyPart.builder()
                        .blobId(upload.getBlobId())
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
}
