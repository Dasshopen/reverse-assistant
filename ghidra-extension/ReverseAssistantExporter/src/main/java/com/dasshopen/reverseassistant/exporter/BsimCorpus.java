package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

public record BsimCorpus(String id, String name, String databaseUrl) {

    public BsimCorpus {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(databaseUrl, "databaseUrl must not be null");
    }
}
