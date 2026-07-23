package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

public record FidCandidate(
    String name,
    String libraryFamily,
    String libraryVersion,
    String libraryVariant,
    float overallScore,
    String matchMode
) {

    public FidCandidate {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(libraryFamily, "libraryFamily must not be null");
        Objects.requireNonNull(libraryVersion, "libraryVersion must not be null");
        Objects.requireNonNull(libraryVariant, "libraryVariant must not be null");
        Objects.requireNonNull(matchMode, "matchMode must not be null");
    }
}
