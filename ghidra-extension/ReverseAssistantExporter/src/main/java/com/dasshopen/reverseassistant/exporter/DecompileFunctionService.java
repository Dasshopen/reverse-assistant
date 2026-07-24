package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class DecompileFunctionService {

    private final DecompileResultJsonWriter jsonWriter;
    private final AtomicUtf8FileWriter fileWriter;
    private final BsimFunctionQueryService bsimQueryService;

    public DecompileFunctionService() {
        jsonWriter = new DecompileResultJsonWriter();
        fileWriter = new AtomicUtf8FileWriter();
        bsimQueryService = new BsimFunctionQueryService();
    }

    // Match Ghidra's native Decompiler window by returning the transient
    // prototype produced for this decompilation. This can be richer than the
    // signature stored in the project and costs only the selected function.
    // FunctionDecompiler falls back to the stored signature when Ghidra does
    // not return a high-level prototype.
    public void decompileAndWrite(
        Program program,
        Address entryAddress,
        Path destination,
        List<BsimCorpus> bsimCorpora,
        TaskMonitor monitor
    ) throws IOException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(entryAddress, "entryAddress must not be null");
        Objects.requireNonNull(destination, "destination must not be null");
        Objects.requireNonNull(bsimCorpora, "bsimCorpora must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        Function function =
            program.getFunctionManager().getFunctionAt(entryAddress);

        if (function == null) {
            throw new IllegalArgumentException(
                "no function exists at address " + entryAddress
            );
        }

        DecompInterface decompiler =
            FunctionDecompiler.createDecompiler(program);

        try {
            DecompiledFunctionDetails details =
                FunctionDecompiler.decompile(function, decompiler, monitor);

            BsimQueryResult bsimResult;

            if (bsimCorpora.isEmpty()) {
                bsimResult = BsimQueryResult.unavailable(
                    "No active BSim corpus is installed."
                );
            }
            else {
                List<BsimCandidate> matches = new ArrayList<>();
                List<String> failures = new ArrayList<>();

                for (BsimCorpus corpus : bsimCorpora) {
                    try {
                        BsimQueryResult result = bsimQueryService.query(
                            program,
                            function,
                            corpus.name(),
                            corpus.databaseUrl(),
                            monitor
                        );
                        matches.addAll(result.matches());
                    }
                    catch (CancelledException exception) {
                        throw exception;
                    }
                    catch (Exception exception) {
                        failures.add(corpus.name() + ": " + exception.getMessage());
                    }
                }

                matches.sort(
                    Comparator.comparingDouble(BsimCandidate::similarity)
                        .thenComparingDouble(BsimCandidate::significance)
                        .reversed()
                );

                if (failures.size() == bsimCorpora.size()) {
                    bsimResult = BsimQueryResult.error(String.join(" | ", failures));
                }
                else {
                    String warning = failures.isEmpty()
                        ? null
                        : "Some BSim corpora could not be queried: " + String.join(" | ", failures);
                    bsimResult = BsimQueryResult.available(matches, warning);
                }
            }

            fileWriter.write(
                destination,
                jsonWriter.write(details, bsimResult)
            );
        }
        finally {
            decompiler.dispose();
        }
    }
}
