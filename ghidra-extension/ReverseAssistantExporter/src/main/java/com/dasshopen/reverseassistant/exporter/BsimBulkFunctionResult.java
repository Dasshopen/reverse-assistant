package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;

public record BsimBulkFunctionResult(
    String entryAddress,
    List<BsimCandidate> candidates,
    boolean scanned,
    String message
) {
    public BsimBulkFunctionResult {
        Objects.requireNonNull(entryAddress, "entryAddress must not be null");
        Objects.requireNonNull(candidates, "candidates must not be null");
        candidates = List.copyOf(candidates);
    }
}
