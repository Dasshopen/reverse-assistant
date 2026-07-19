package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

import ghidra.program.model.listing.Program;

public final class ReverseAssistantExportService {

    private final ProgramMetadataCollector metadataCollector;
    private final GhidraExportJsonWriter jsonWriter;
    private final AtomicUtf8FileWriter fileWriter;
    private final FunctionMetadataCollector functionCollector;

    public ReverseAssistantExportService() {
        metadataCollector = new ProgramMetadataCollector();
        jsonWriter = new GhidraExportJsonWriter();
        fileWriter = new AtomicUtf8FileWriter();
        functionCollector = new FunctionMetadataCollector();
    }

    public void export(Program program, Path destination)
        throws IOException {

        Objects.requireNonNull(
            program,
            "program must not be null"
        );
        Objects.requireNonNull(
            destination,
            "destination must not be null"
        );

        ProgramMetadata metadata =
            metadataCollector.collect(program);

        String json = jsonWriter.write(
            metadata,
            functionCollector.collect(program)
        );

        fileWriter.write(destination, json);
    }
}