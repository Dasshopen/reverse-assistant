package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

public record EnumValueMetadata(
    String name,
    long value
) {

    public EnumValueMetadata {
        Objects.requireNonNull(name, "name must not be null");
    }
}
