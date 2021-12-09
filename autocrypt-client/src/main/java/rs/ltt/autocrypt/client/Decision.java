package rs.ltt.autocrypt.client;

import com.google.common.collect.Iterables;
import java.util.Collection;
import java.util.Objects;

public enum Decision {
    DISABLE,
    DISCOURAGE,
    AVAILABLE,
    ENCRYPT;

    public static Decision combine(final Collection<Decision> decisions) {
        if (decisions.contains(DISABLE)) {
            return DISABLE;
        }
        if (Iterables.all(decisions, d -> Objects.equals(d, ENCRYPT))) {
            return ENCRYPT;
        }
        if (decisions.contains(DISCOURAGE)) {
            return DISCOURAGE;
        }
        return AVAILABLE;
    }
}
