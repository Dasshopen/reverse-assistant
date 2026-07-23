package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

public record BsimCandidate(
    String name,
    String executable,
    double similarity,
    double significance
) {

    public BsimCandidate {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(executable, "executable must not be null");
    }
}
