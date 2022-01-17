package rs.ltt.autocrypt.client.state;

import com.google.common.base.Preconditions;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Multimap;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import rs.ltt.autocrypt.client.header.AutocryptHeader;

public class GossipUpdate extends AbstractAutocryptUpdate {

    private GossipUpdate(final String from, final Instant effectiveDate, final byte[] keyData) {
        super(from, effectiveDate, keyData);
    }

    public static Builder builder(final Instant effectiveDate) {
        return new Builder(effectiveDate);
    }

    public static class Builder implements GossipRetriever {

        private final Instant effectiveDate;
        private final Multimap<String, GossipUpdate> gossipUpdates = ArrayListMultimap.create();

        private Builder(final Instant effectiveDate) {
            this.effectiveDate = effectiveDate;
        }

        public Builder add(final String header) {
            final AutocryptHeader autocryptHeader;
            try {
                autocryptHeader = AutocryptHeader.parse(header);
            } catch (final Exception e) {
                // improperly formatted headers will just be ignored
                return this;
            }
            return add(autocryptHeader);
        }

        public Builder add(final AutocryptHeader header) {
            Preconditions.checkNotNull(header);
            final GossipUpdate gossipUpdate =
                    new GossipUpdate(header.getAddress(), effectiveDate, header.getKeyData());
            this.gossipUpdates.put(gossipUpdate.getFrom(), gossipUpdate);
            return this;
        }

        public List<GossipUpdate> build() {
            final ImmutableList.Builder<GossipUpdate> updateBuilder = new ImmutableList.Builder<>();
            for (final Collection<GossipUpdate> updates : this.gossipUpdates.asMap().values()) {
                if (Iterables.size(updates) == 1) {
                    updateBuilder.addAll(updates);
                }
            }
            return updateBuilder.build();
        }

        @Override
        public void onAutocryptGossipHeader(final AutocryptHeader autocryptHeader) {
            if (autocryptHeader.getAddress() == null) {
                throw new IllegalStateException(
                        "Received illegal AutocryptHeader. Address MUST be set");
            }
            this.add(autocryptHeader);
        }
    }
}
