package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

public record TypeUsageMetadata(
    String kind,
    String functionAddress,
    String functionName,
    String parameterName,
    String dataAddress,
    String dataLabel
) {

    public static final String KIND_FUNCTION_PARAMETER = "function_parameter";
    public static final String KIND_FUNCTION_RETURN = "function_return";
    public static final String KIND_GLOBAL_DATA = "global_data";

    private static final Set<String> VALID_KINDS = Set.of(
        KIND_FUNCTION_PARAMETER,
        KIND_FUNCTION_RETURN,
        KIND_GLOBAL_DATA
    );

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public TypeUsageMetadata {
        Objects.requireNonNull(kind, "kind must not be null");

        if (!VALID_KINDS.contains(kind)) {
            throw new IllegalArgumentException(
                "kind must be one of " + VALID_KINDS + " but was: " + kind
            );
        }

        if (functionAddress != null &&
            !ADDRESS_PATTERN.matcher(functionAddress).matches()) {
            throw new IllegalArgumentException(
                "functionAddress must be null or use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }

        if (dataAddress != null &&
            !ADDRESS_PATTERN.matcher(dataAddress).matches()) {
            throw new IllegalArgumentException(
                "dataAddress must be null or use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }
    }
}
