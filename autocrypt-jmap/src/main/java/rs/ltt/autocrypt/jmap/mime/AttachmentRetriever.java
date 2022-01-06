package rs.ltt.autocrypt.jmap.mime;

import java.io.IOException;
import java.io.InputStream;
import rs.ltt.jmap.common.entity.Attachment;

public interface AttachmentRetriever {

    long onAttachmentRetrieved(final Attachment attachment, final InputStream inputStream)
            throws IOException;
}
