package rs.ltt.autocrypt.client.header;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import lombok.Getter;
import lombok.ToString;

import java.util.List;

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
        final ImmutableList.Builder<Attribute> builder = new ImmutableList.Builder<>();
        StringBuilder keyBuilder = new StringBuilder();
        StringBuilder valueBuilder = null;
        boolean inQuote = false;
        for (final char c : attributes.toCharArray()) {
            if (!inQuote) {
                if (c == ';') {
                    builder.add(of(keyBuilder, valueBuilder));
                    keyBuilder = new StringBuilder();
                    valueBuilder = null;
                    continue;
                } else if (c == '=' && valueBuilder == null) {
                    valueBuilder = new StringBuilder();
                    continue;
                }
            }
            if (c == '"') {
                inQuote = !inQuote;
            }
            if (valueBuilder != null) {
                valueBuilder.append(c);
            } else if (!Character.isWhitespace(c) || keyBuilder.length() > 0) {
                keyBuilder.append(c);
            }
        }
        if (inQuote) {
            throw new IllegalArgumentException("Unexpected end (quotation not closed)");
        }
        if (keyBuilder.length() > 0 || valueBuilder != null) {
            builder.add(of(keyBuilder, valueBuilder));
        }
        return builder.build();
    }

    private static Attribute of(final StringBuilder keyBuilder, final StringBuilder valueBuilder) {
        Preconditions.checkNotNull(keyBuilder);
        final String key = keyBuilder.toString();
        if (key.isEmpty()) {
            throw new IllegalArgumentException("Attribute name can not be empty");
        }
        return new Attribute(keyBuilder.toString(), valueBuilder == null ? null : valueBuilder.toString());
    }
}
