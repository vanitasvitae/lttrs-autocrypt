package rs.ltt.autocrypt.jmap;

import com.google.common.base.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.jmap.common.entity.BinaryData;
import rs.ltt.jmap.common.entity.Downloadable;
import rs.ltt.jmap.common.entity.Email;

public class EncryptedBodyPartTest {

    @Test
    public void createAndFindEncryptedBodyPart() {

        final BinaryData stubBinaryData =
                new BinaryData() {
                    @Override
                    public String getBlobId() {
                        return "my-blob-id";
                    }

                    @Override
                    public String getType() {
                        throw new IllegalStateException("Not implemented");
                    }

                    @Override
                    public Long getSize() {
                        throw new IllegalStateException("Not implemented");
                    }
                };

        final Email.EmailBuilder emailBuilder = Email.builder();
        final Email email =
                EncryptedBodyPart.insertEncryptedBlob(emailBuilder, stubBinaryData).build();

        final Optional<Downloadable> blob = EncryptedBodyPart.findEncryptedBodyPart(email);

        Assertions.assertTrue(blob.isPresent());

        final Downloadable downloadable = blob.get();

        Assertions.assertEquals("my-blob-id", downloadable.getBlobId());
        Assertions.assertEquals("encrypted.asc", downloadable.getName());
    }

    @Test
    public void noBodyStructure() {
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> EncryptedBodyPart.findEncryptedBodyPart(Email.builder().build()));
    }
}
