package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public final class GhidraExportJsonWriter {

    private static final int SCHEMA_VERSION = 1;

    private final Gson gson;

    public GhidraExportJsonWriter() {
        gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();
    }

    public String write(ProgramMetadata metadata) {
        Objects.requireNonNull(
            metadata,
            "metadata must not be null"
        );

        JsonObject root = new JsonObject();
        root.addProperty("schema_version", SCHEMA_VERSION);
        root.add("program", createProgramObject(metadata));
        root.add("functions", new JsonArray());

        return gson.toJson(root) + "\n";
    }

    private static JsonObject createProgramObject(
        ProgramMetadata metadata
    ) {
        JsonObject program = new JsonObject();

        program.addProperty("name", metadata.name());
        program.addProperty("sha256", metadata.sha256());
        program.addProperty("format", metadata.format());
        program.addProperty(
            "architecture",
            metadata.architecture()
        );
        program.addProperty(
            "endianness",
            metadata.endianness()
        );
        program.addProperty(
            "image_base",
            metadata.imageBase()
        );
        JsonArray entryPoints = new JsonArray();

        for (String entryPoint : metadata.entryPoints()) {
            entryPoints.add(entryPoint);
        }

        program.add("entry_points", entryPoints);

        return program;
    }
}