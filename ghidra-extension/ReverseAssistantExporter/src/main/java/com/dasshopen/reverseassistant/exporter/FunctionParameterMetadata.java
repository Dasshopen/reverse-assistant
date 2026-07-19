package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

public record FunctionParameterMetadata(
    String name,
    String dataType
) {

    public FunctionParameterMetadata {
        Objects.requireNonNull(
            name,
            "name must not be null"
        );
        Objects.requireNonNull(
            dataType,
            "dataType must not be null"
        );
    }
}