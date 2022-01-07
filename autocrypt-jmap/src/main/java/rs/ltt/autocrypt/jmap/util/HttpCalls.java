package rs.ltt.autocrypt.jmap.util;

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import okhttp3.Call;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpCalls {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCalls.class);

    private HttpCalls() {}

    public static void cancelCallOnCancel(final ListenableFuture<?> future, final Call call) {
        addCompletionHook(
                future,
                () -> {
                    if (future.isCancelled()) {
                        LOGGER.debug("Cancel OkHttp.Call after future was cancelled");
                        call.cancel();
                    }
                });
    }

    private static ListenableFuture<?> addCompletionHook(
            final ListenableFuture<?> future, final Runnable runnable) {
        return Futures.whenAllComplete(future).run(runnable, MoreExecutors.directExecutor());
    }
}
