package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;

public record FunctionIdentification(
    String entryAddress,
    List<FidCandidate> candidates
) {

    public FunctionIdentification {
        Objects.requireNonNull(entryAddress, "entryAddress must not be null");
        Objects.requireNonNull(candidates, "candidates must not be null");

        candidates = List.copyOf(candidates);
    }
}
