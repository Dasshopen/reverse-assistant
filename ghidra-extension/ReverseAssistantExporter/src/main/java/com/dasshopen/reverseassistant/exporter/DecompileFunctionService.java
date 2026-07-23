package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.file.Path;
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

    public DecompileFunctionService() {
        jsonWriter = new DecompileResultJsonWriter();
        fileWriter = new AtomicUtf8FileWriter();
    }

    // Scoping "Decompiler Parameter ID" to a single function (or even that
    // function plus its direct callers) was tried and measured: it reports
    // success but recovers zero parameters, because register-parameter
    // identification needs whole-program call-site context that a bounded
    // scope can't provide. Parameters/return type/calling convention below
    // therefore reflect the function's existing signature as-is; pseudocode
    // stays available and generally readable, but variables the analyzer
    // would have bound to parameters may appear as raw registers (e.g. in_RCX).
    public void decompileAndWrite(
        Program program,
        Address entryAddress,
        Path destination,
        TaskMonitor monitor
    ) throws IOException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(entryAddress, "entryAddress must not be null");
        Objects.requireNonNull(destination, "destination must not be null");
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
            String decompiledCode =
                FunctionDecompiler.decompile(function, decompiler, monitor);

            String callingConvention = function.getCallingConventionName();

            DecompiledFunctionDetails details = new DecompiledFunctionDetails(
                decompiledCode,
                FunctionDecompiler.formatDataType(function.getReturnType()),
                FunctionDecompiler.extractParameters(function),
                callingConvention == null ? "unknown" : callingConvention
            );

            fileWriter.write(destination, jsonWriter.write(details));
        }
        finally {
            decompiler.dispose();
        }
    }
}
