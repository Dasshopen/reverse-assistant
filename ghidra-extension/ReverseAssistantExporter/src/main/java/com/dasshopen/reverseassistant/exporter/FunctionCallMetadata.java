package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;
import java.util.regex.Pattern;

public record FunctionCallMetadata(
    String targetAddress,
    String targetName
) {

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public FunctionCallMetadata {
        Objects.requireNonNull(
            targetName,
            "targetName must not be null"
        );

        if (targetAddress != null &&
            !ADDRESS_PATTERN.matcher(targetAddress).matches()) {
            throw new IllegalArgumentException(
                "targetAddress must be null or use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }
    }
}