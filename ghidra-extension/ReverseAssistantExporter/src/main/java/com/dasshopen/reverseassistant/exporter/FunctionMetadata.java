package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

public record FunctionMetadata(
    String entryAddress,
    String name,
    String returnType,
    List<FunctionParameterMetadata> parameters,
    boolean isExternal,
    boolean isThunk,
    String decompiledCode,
    List<FunctionCallMetadata> calls,
    String libraryName,
    String thunkTargetAddress,
    String namespace
) {

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public FunctionMetadata {
        Objects.requireNonNull(
            entryAddress,
            "entryAddress must not be null"
        );
        Objects.requireNonNull(
            name,
            "name must not be null"
        );
        Objects.requireNonNull(
            returnType,
            "returnType must not be null"
        );
        Objects.requireNonNull(
            parameters,
            "parameters must not be null"
        );
        Objects.requireNonNull(
            calls,
            "calls must not be null"
        );

        if (!ADDRESS_PATTERN.matcher(entryAddress).matches()) {
            throw new IllegalArgumentException(
                "entryAddress must use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }

        if (thunkTargetAddress != null &&
            !ADDRESS_PATTERN.matcher(thunkTargetAddress).matches()) {
            throw new IllegalArgumentException(
                "thunkTargetAddress must use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }

        parameters = List.copyOf(parameters);
        calls = List.copyOf(calls);
    }
}