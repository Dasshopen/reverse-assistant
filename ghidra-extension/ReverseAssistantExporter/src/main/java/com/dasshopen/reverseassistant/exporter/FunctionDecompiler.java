package com.dasshopen.reverseassistant.exporter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class FunctionDecompiler {

    private FunctionDecompiler() {
    }

    public static DecompInterface createDecompiler(
        Program program
    ) {
        DecompileOptions options =
            new DecompileOptions();

        options.grabFromProgram(program);

        DecompInterface decompiler =
            new DecompInterface();

        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);

        if (!decompiler.openProgram(program)) {
            String message = decompiler.getLastMessage();

            decompiler.dispose();

            throw new IllegalStateException(
                "Unable to initialize Ghidra decompiler: " +
                    message
            );
        }

        return decompiler;
    }

    public static String decompile(
        Function function,
        DecompInterface decompiler,
        TaskMonitor monitor
    ) throws CancelledException {
        if (function.isExternal()) {
            return null;
        }

        DecompileResults results =
            decompiler.decompileFunction(
                function,
                DecompileOptions
                    .SUGGESTED_DECOMPILE_TIMEOUT_SECS,
                monitor
            );

        monitor.checkCancelled();

        if (results == null ||
            !results.decompileCompleted()) {
            return null;
        }

        DecompiledFunction decompiledFunction =
            results.getDecompiledFunction();

        if (decompiledFunction == null) {
            return null;
        }

        String code = decompiledFunction.getC();

        if (code == null || code.isBlank()) {
            return null;
        }

        return code;
    }
}
