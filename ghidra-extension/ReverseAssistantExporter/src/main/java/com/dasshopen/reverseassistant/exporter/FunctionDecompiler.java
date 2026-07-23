package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
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
        // Ghidra's native Decompiler window renders the prototype returned by
        // the decompiler, not only the signature currently stored in the
        // program database. Keep the syntax tree so getHighFunction() exposes
        // that same transient prototype for the selected function.
        decompiler.toggleSyntaxTree(true);

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

    public static DecompiledFunctionDetails decompile(
        Function function,
        DecompInterface decompiler,
        TaskMonitor monitor
    ) throws CancelledException {
        if (function.isExternal()) {
            return detailsFromStoredSignature(function, null);
        }

        DecompileResults results =
            decompiler.decompileFunction(
                function,
                DecompileOptions
                    .SUGGESTED_DECOMPILE_TIMEOUT_SECS,
                monitor
            );

        monitor.checkCancelled();

        if (results == null || !results.decompileCompleted()) {
            return detailsFromStoredSignature(function, null);
        }

        DecompiledFunction decompiledFunction =
            results.getDecompiledFunction();

        String code = null;

        if (decompiledFunction != null) {
            String candidateCode = decompiledFunction.getC();

            if (candidateCode != null && !candidateCode.isBlank()) {
                code = candidateCode;
            }
        }

        HighFunction highFunction = results.getHighFunction();

        if (highFunction == null) {
            return detailsFromStoredSignature(function, code);
        }

        FunctionPrototype prototype =
            highFunction.getFunctionPrototype();

        if (prototype == null) {
            return detailsFromStoredSignature(function, code);
        }

        String callingConvention = prototype.getModelName();

        return new DecompiledFunctionDetails(
            code,
            formatDataType(prototype.getReturnType()),
            extractParameters(prototype),
            callingConvention == null || callingConvention.isBlank()
                ? "unknown"
                : callingConvention
        );
    }

    private static DecompiledFunctionDetails detailsFromStoredSignature(
        Function function,
        String decompiledCode
    ) {
        String callingConvention = function.getCallingConventionName();

        return new DecompiledFunctionDetails(
            decompiledCode,
            formatDataType(function.getReturnType()),
            extractParameters(function),
            callingConvention == null || callingConvention.isBlank()
                ? "unknown"
                : callingConvention
        );
    }

    private static List<FunctionParameterMetadata> extractParameters(
        FunctionPrototype prototype
    ) {
        List<FunctionParameterMetadata> collectedParameters =
            new ArrayList<>(prototype.getNumParams());

        for (int index = 0; index < prototype.getNumParams(); index++) {
            HighSymbol parameter = prototype.getParam(index);

            if (parameter == null) {
                continue;
            }

            String parameterName = parameter.getName();

            collectedParameters.add(
                new FunctionParameterMetadata(
                    parameterName == null ? "" : parameterName,
                    formatDataType(parameter.getDataType())
                )
            );
        }

        return List.copyOf(collectedParameters);
    }

    public static List<FunctionParameterMetadata> extractParameters(
        Function function
    ) {
        Parameter[] parameters = function.getParameters();

        List<FunctionParameterMetadata> collectedParameters =
            new ArrayList<>(parameters.length);

        for (Parameter parameter : parameters) {
            String parameterName = parameter.getName();

            collectedParameters.add(
                new FunctionParameterMetadata(
                    parameterName == null ? "" : parameterName,
                    formatDataType(parameter.getDataType())
                )
            );
        }

        return List.copyOf(collectedParameters);
    }

    public static String formatDataType(DataType dataType) {
        if (dataType == null) {
            return "unknown";
        }

        return dataType.getDisplayName();
    }
}
