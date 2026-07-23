package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

public final class ReverseAssistantExportService {

    private final ProgramMetadataCollector metadataCollector;
    private final GhidraExportJsonWriter jsonWriter;
    private final AtomicUtf8FileWriter fileWriter;
    private final FunctionMetadataCollector functionCollector;
    private final ProgramStringsCollector stringsCollector;

    public ReverseAssistantExportService() {
        metadataCollector = new ProgramMetadataCollector();
        jsonWriter = new GhidraExportJsonWriter();
        fileWriter = new AtomicUtf8FileWriter();
        functionCollector = new FunctionMetadataCollector();
        stringsCollector = new ProgramStringsCollector();
    }

    public void export(
        Program program,
        Path destination,
        TaskMonitor monitor
    ) throws IOException, CancelledException {

        Objects.requireNonNull(
            program,
            "program must not be null"
        );
        Objects.requireNonNull(
            destination,
            "destination must not be null"
        );
        Objects.requireNonNull(
        monitor,
            "monitor must not be null"
        );

        ProgramMetadata metadata =
            metadataCollector.collect(program);

        String json = jsonWriter.write(
            metadata,
            functionCollector.collect(program, monitor),
            stringsCollector.collect(program, monitor)
        );

        fileWriter.write(destination, json);
    }
}