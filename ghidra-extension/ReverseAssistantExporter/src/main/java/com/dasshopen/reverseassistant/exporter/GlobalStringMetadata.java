package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

public record GlobalStringMetadata(
    String address,
    String value,
    List<StringReferenceMetadata> references
) {

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public GlobalStringMetadata {
        Objects.requireNonNull(address, "address must not be null");
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(references, "references must not be null");

        if (!ADDRESS_PATTERN.matcher(address).matches()) {
            throw new IllegalArgumentException(
                "address must use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }

        references = List.copyOf(references);
    }
}
