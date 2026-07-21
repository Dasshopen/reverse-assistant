package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public final class FunctionMetadataCollector {

    public List<FunctionMetadata> collect(Program program) {
        Objects.requireNonNull(
            program,
            "program must not be null"
        );

        FunctionManager functionManager =
            program.getFunctionManager();

        List<Function> functions = new ArrayList<>();

        addFunctions(
            functions,
            functionManager.getFunctions(true)
        );
        addFunctions(
            functions,
            functionManager.getExternalFunctions()
        );

        functions.sort(createFunctionComparator());

        List<FunctionMetadata> collectedFunctions =
            new ArrayList<>(functions.size());

        Set<String> entryAddresses = new HashSet<>();

        for (Function function : functions) {
            FunctionMetadata metadata =
                collectFunction(program, function);

            if (!entryAddresses.add(metadata.entryAddress())) {
                throw new IllegalStateException(
                    "Duplicate exported function address: " +
                        metadata.entryAddress()
                );
            }

            collectedFunctions.add(metadata);
        }

        return List.copyOf(collectedFunctions);
    }

    private static void addFunctions(
        List<Function> destination,
        FunctionIterator iterator
    ) {
        while (iterator.hasNext()) {
            destination.add(iterator.next());
        }
    }

    private static Comparator<Function>
        createFunctionComparator() {

        return (left, right) -> {
            int addressComparison = Long.compareUnsigned(
                left.getEntryPoint().getOffset(),
                right.getEntryPoint().getOffset()
            );

            if (addressComparison != 0) {
                return addressComparison;
            }

            int spaceComparison = left.getEntryPoint()
                .getAddressSpace()
                .getName()
                .compareTo(
                    right.getEntryPoint()
                        .getAddressSpace()
                        .getName()
                );

            if (spaceComparison != 0) {
                return spaceComparison;
            }

            return left.getName().compareTo(
                right.getName()
            );
        };
    }

    private static FunctionMetadata collectFunction(
        Program program,
        Function function
    ) {
        return new FunctionMetadata(
            formatAddress(function),
            function.getName(),
            formatDataType(function.getReturnType()),
            collectParameters(function),
            function.isExternal(),
            function.isThunk(),
            null,
            collectCalls(function),
            collectStrings(program, function)
        );
    }

    private static List<FunctionParameterMetadata>
        collectParameters(Function function) {

        Parameter[] parameters = function.getParameters();

        List<FunctionParameterMetadata> collectedParameters =
            new ArrayList<>(parameters.length);

        for (Parameter parameter : parameters) {
            String parameterName = parameter.getName();

            if (parameterName == null) {
                parameterName = "";
            }

            collectedParameters.add(
                new FunctionParameterMetadata(
                    parameterName,
                    formatDataType(parameter.getDataType())
                )
            );
        }

        return List.copyOf(collectedParameters);
    }

    private static List<FunctionCallMetadata> collectCalls(
        Function function
    ) {
        List<Function> calledFunctions = new ArrayList<>(
            function.getCalledFunctions(TaskMonitor.DUMMY)
    );

        calledFunctions.sort(createFunctionComparator());

        List<FunctionCallMetadata> calls =
            new ArrayList<>(calledFunctions.size());

        Set<String> targetAddresses = new HashSet<>();

        for (Function calledFunction : calledFunctions) {
            String targetAddress =
                formatAddress(calledFunction);

            if (!targetAddresses.add(targetAddress)) {
                continue;
            }

            calls.add(
                new FunctionCallMetadata(
                    targetAddress,
                    calledFunction.getName()
                )
            );
        }

        return List.copyOf(calls);
    }

    private static List<String> collectStrings(
        Program program,
        Function function
    ) {
        if (function.isExternal()) {
            return List.of();
        }

        Listing listing = program.getListing();

        InstructionIterator instructions =
            listing.getInstructions(
                function.getBody(),
                true
            );

        Set<String> strings = new TreeSet<>();

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();

            for (Reference reference :
                instruction.getReferencesFrom()) {

                Data data = listing.getDefinedDataContaining(
                    reference.getToAddress()
                );

                if (data == null || !data.hasStringValue()) {
                    continue;
                }

                Object value = data.getValue();

                if (value instanceof String stringValue) {
                    strings.add(stringValue);
                }
            }
        }

        return List.copyOf(strings);
    }

    private static String formatDataType(DataType dataType) {
        if (dataType == null) {
            return "unknown";
        }

        return dataType.getDisplayName();
    }

    private static String formatAddress(Function function) {
        return "0x" + Long.toUnsignedString(
            function.getEntryPoint().getOffset(),
            16
        );
    }
}