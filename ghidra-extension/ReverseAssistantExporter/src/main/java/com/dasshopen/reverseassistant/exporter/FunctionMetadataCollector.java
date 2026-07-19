package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;

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
                collectFunction(function);

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
            List.of(),
            List.of()
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