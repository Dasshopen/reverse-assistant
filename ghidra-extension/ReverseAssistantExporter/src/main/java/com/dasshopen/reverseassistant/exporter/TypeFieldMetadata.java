package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

public record TypeFieldMetadata(
    String name,
    String dataType,
    int offset
) {

    public TypeFieldMetadata {
        Objects.requireNonNull(dataType, "dataType must not be null");
    }
}
