package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;
import java.util.regex.Pattern;

public record StringReferenceMetadata(
    String instructionAddress,
    String functionAddress
) {

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public StringReferenceMetadata {
        Objects.requireNonNull(
            instructionAddress,
            "instructionAddress must not be null"
        );

        if (!ADDRESS_PATTERN.matcher(instructionAddress).matches()) {
            throw new IllegalArgumentException(
                "instructionAddress must use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }

        if (functionAddress != null &&
            !ADDRESS_PATTERN.matcher(functionAddress).matches()) {
            throw new IllegalArgumentException(
                "functionAddress must be null or use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }
    }
}
