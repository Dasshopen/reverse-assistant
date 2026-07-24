package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;

public record BsimQueryResult(
    String status,
    List<BsimCandidate> matches,
    String message
) {

    public static final String AVAILABLE = "available";
    public static final String UNAVAILABLE = "unavailable";
    public static final String ERROR = "error";

    public BsimQueryResult {
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(matches, "matches must not be null");
        matches = List.copyOf(matches);
    }

    public static BsimQueryResult available(List<BsimCandidate> matches) {
        return new BsimQueryResult(AVAILABLE, matches, null);
    }

    public static BsimQueryResult available(List<BsimCandidate> matches, String message) {
        return new BsimQueryResult(AVAILABLE, matches, message);
    }

    public static BsimQueryResult unavailable(String message) {
        return new BsimQueryResult(UNAVAILABLE, List.of(), message);
    }

    public static BsimQueryResult error(String message) {
        return new BsimQueryResult(ERROR, List.of(), message);
    }
}
