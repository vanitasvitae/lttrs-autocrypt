package rs.ltt.autocrypt.client.header;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import java.util.List;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class Attribute {

    private final String key;
    private final String value;

    public Attribute(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public static List<Attribute> parse(final String attributes) {
        final ImmutableList.Builder<Attribute> listBuilder = new ImmutableList.Builder<>();
        final ContinuousAttributeBuilder attributeBuilder = new ContinuousAttributeBuilder();
        boolean inQuote = false;
        for (final char c : attributes.toCharArray()) {
            if (!inQuote) {
                if (c == ';') {
                    listBuilder.add(attributeBuilder.build());
                    continue;
                } else if (c == '=' && attributeBuilder.isReadingAttributeName()) {
                    attributeBuilder.beginValue();
                    continue;
                }
            }
            if (c == '"') {
                inQuote = !inQuote;
            }
            attributeBuilder.append(c);
        }
        if (inQuote) {
            throw new IllegalArgumentException("Unexpected end (quotation not closed)");
        }
        if (attributeBuilder.hasPendingAttribute()) {
            listBuilder.add(attributeBuilder.build());
        }
        return listBuilder.build();
    }

    private static Attribute of(final StringBuilder keyBuilder, final StringBuilder valueBuilder) {
        Preconditions.checkNotNull(keyBuilder);
        final String key = keyBuilder.toString();
        if (key.isEmpty()) {
            throw new IllegalArgumentException("Attribute name can not be empty");
        }
        return new Attribute(
                keyBuilder.toString(), valueBuilder == null ? null : valueBuilder.toString());
    }

    private static class ContinuousAttributeBuilder {
        private StringBuilder keyBuilder = new StringBuilder();
        private StringBuilder valueBuilder = null;

        public Attribute build() {
            final Attribute attribute = Attribute.of(keyBuilder, valueBuilder);
            this.keyBuilder = new StringBuilder();
            this.valueBuilder = null;
            return attribute;
        }

        public void beginValue() {
            this.valueBuilder = new StringBuilder();
        }

        public boolean isReadingAttributeName() {
            return this.valueBuilder == null;
        }

        public boolean hasPendingAttribute() {
            return keyBuilder.length() > 0 || valueBuilder != null;
        }

        public void append(final char c) {
            if (valueBuilder != null) {
                valueBuilder.append(c);
            } else if (!Character.isWhitespace(c) || keyBuilder.length() > 0) {
                keyBuilder.append(c);
            }
        }
    }
}
