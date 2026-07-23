package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

public final class FunctionMetadataCollector {

    // Ghidra's own placeholder namespace for external functions whose real
    // source library it could not determine (observed for every ELF import
    // in testing -- ELF imports are not attributed to their real .so this
    // way, unlike PE imports, which land in a namespace named after the
    // real DLL). Never surfaced as if it were a real library name.
    private static final String UNKNOWN_LIBRARY_NAMESPACE = "<EXTERNAL>";

    public List<FunctionMetadata> collect(
        Program program,
        TaskMonitor monitor
    ) throws CancelledException {
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

        monitor.initialize(
            functions.size(),
            "Exporting function metadata"
        );

        List<FunctionMetadata> collectedFunctions =
            new ArrayList<>(functions.size());

        Set<String> entryAddresses = new HashSet<>();

        for (Function function : functions) {
            monitor.checkCancelled();

            monitor.setMessage(
                "Exporting function: " + function.getName()
            );

            FunctionMetadata metadata =
                collectFunction(function);

            if (!entryAddresses.add(metadata.entryAddress())) {
                throw new IllegalStateException(
                    "Duplicate exported function address: " +
                        metadata.entryAddress()
                );
            }

            collectedFunctions.add(metadata);
            monitor.increment();
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
        // Decompiling every function during bulk export was the dominant cost of
        // headless analysis. Pseudocode is decompiled on demand instead, via
        // DecompileFunctionService/FunctionDecompiler, one function at a time.
        return new FunctionMetadata(
            formatAddress(function),
            function.getName(),
            FunctionDecompiler.formatDataType(function.getReturnType()),
            FunctionDecompiler.extractParameters(function),
            function.isExternal(),
            function.isThunk(),
            null,
            collectCalls(function),
            collectLibraryName(function),
            collectThunkTargetAddress(function),
            collectNamespace(function)
        );
    }

    private static String collectLibraryName(Function function) {
        if (!function.isExternal()) {
            return null;
        }

        String namespaceName = function.getParentNamespace().getName();

        return UNKNOWN_LIBRARY_NAMESPACE.equals(namespaceName) ? null : namespaceName;
    }

    // Fully qualified parent namespace (e.g. a C++ class or a compilation
    // unit's static-linkage namespace), used to disambiguate same-named
    // functions when comparing two analyses. Null for the global namespace
    // and for Ghidra's generic external placeholder -- neither is a real,
    // meaningful namespace to match on.
    private static String collectNamespace(Function function) {
        Namespace namespace = function.getParentNamespace();

        if (namespace == null || namespace.isGlobal()) {
            return null;
        }

        String qualifiedName = namespace.getName(true);

        return UNKNOWN_LIBRARY_NAMESPACE.equals(qualifiedName) ? null : qualifiedName;
    }

    // Non-recursive: a thunk's body is often just a jump, so Ghidra's own
    // per-function `calls` list (built from real CALL instructions) misses
    // the redirection entirely. Deliberately the *immediate* target only
    // (not the fully-resolved chain) so multi-level thunk chains and cycles
    // are represented explicitly in the export rather than silently
    // collapsed -- Rust walks the chain itself when it needs the final
    // target (e.g. resolving an import's real callers).
    private static String collectThunkTargetAddress(Function function) {
        if (!function.isThunk()) {
            return null;
        }

        Function thunkedFunction = function.getThunkedFunction(false);

        return thunkedFunction == null ? null : formatAddress(thunkedFunction);
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

    private static String formatAddress(Function function) {
        return "0x" + Long.toUnsignedString(
            function.getEntryPoint().getOffset(),
            16
        );
    }
}