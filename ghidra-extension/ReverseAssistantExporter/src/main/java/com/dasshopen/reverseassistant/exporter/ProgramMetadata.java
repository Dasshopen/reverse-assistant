package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;
import java.util.regex.Pattern;
import java.util.List;

public record ProgramMetadata(
    String name,
    String sha256,
    String format,
    String architecture,
    String endianness,
    String imageBase,
    List<ExternalEntryPointMetadata> externalEntryPoints,
    List<String> requiredLibraries
) {

    private static final Pattern SHA_256_PATTERN =
        Pattern.compile("[0-9a-f]{64}");

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public ProgramMetadata {
        name = requireNonBlank(name, "name");
        sha256 = requireNonBlank(sha256, "sha256");
        format = requireNonBlank(format, "format");
        architecture = requireNonBlank(architecture, "architecture");
        endianness = requireNonBlank(endianness, "endianness");
        imageBase = requireNonBlank(imageBase, "imageBase");
        Objects.requireNonNull(
            externalEntryPoints,
            "externalEntryPoints must not be null"
        );
        externalEntryPoints = List.copyOf(externalEntryPoints);

        Objects.requireNonNull(
            requiredLibraries,
            "requiredLibraries must not be null"
        );
        requiredLibraries = List.copyOf(requiredLibraries);

        if (!SHA_256_PATTERN.matcher(sha256).matches()) {
            throw new IllegalArgumentException(
                "sha256 must contain exactly 64 lowercase hexadecimal characters"
            );
        }

        if (!endianness.equals("little") && !endianness.equals("big")) {
            throw new IllegalArgumentException(
                "endianness must be either little or big"
            );
        }

        validateAddress(imageBase, "imageBase");
    }

    private static String requireNonBlank(String value, String fieldName) {
        Objects.requireNonNull(value, fieldName + " must not be null");

        if (value.isBlank()) {
            throw new IllegalArgumentException(
                fieldName + " must not be blank"
            );
        }

        return value;
    }

    private static void validateAddress(
        String value,
        String fieldName
    ) {
        Objects.requireNonNull(
            value,
            fieldName + " must not be null"
        );

        if (!ADDRESS_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException(
                fieldName +
                " must use the format 0x followed by " +
                "lowercase hexadecimal digits"
            );
        }
    }
}