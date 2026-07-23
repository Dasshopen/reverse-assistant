package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// Structures, unions, enums and typedefs actually relevant to this binary:
// starts from every type directly used by a function signature (parameter
// or return type) or a defined global data item, then recursively pulls in
// whatever those types themselves reference (struct/union fields, a
// typedef's target) -- a struct field or typedef target is never a "usage"
// in its own right, only the seeds are. This mirrors why only *referenced*
// strings are exported (see ProgramStringsCollector): the vast majority of
// a real PDB/DWARF program's DataTypeManager is compiler/runtime noise
// (RTTI helpers, unused Windows headers, ...) never touched by the actual
// program logic, and walking the whole manager would bury the real answer
// in that noise.
public final class ProgramTypesCollector {

    private static final String ANONYMOUS_NAME_PREFIX = "<unnamed";

    public List<DetectedTypeMetadata> collect(
        Program program,
        TaskMonitor monitor
    ) throws CancelledException {
        Map<TypeKey, DataType> discovered = new LinkedHashMap<>();
        Map<TypeKey, List<TypeUsageMetadata>> usagesByType = new LinkedHashMap<>();
        Deque<DataType> pending = new ArrayDeque<>();

        collectFunctionUsages(program, monitor, discovered, usagesByType, pending);
        collectGlobalDataUsages(program, monitor, discovered, usagesByType, pending);
        expandClosure(monitor, discovered, pending);

        List<DetectedTypeMetadata> result = new ArrayList<>(discovered.size());

        for (Map.Entry<TypeKey, DataType> entry : discovered.entrySet()) {
            result.add(buildMetadata(
                entry.getValue(),
                usagesByType.getOrDefault(entry.getKey(), List.of())
            ));
        }

        result.sort(
            Comparator.comparing(DetectedTypeMetadata::category)
                .thenComparing(DetectedTypeMetadata::name)
        );

        return List.copyOf(result);
    }

    private static void collectFunctionUsages(
        Program program,
        TaskMonitor monitor,
        Map<TypeKey, DataType> discovered,
        Map<TypeKey, List<TypeUsageMetadata>> usagesByType,
        Deque<DataType> pending
    ) throws CancelledException {
        FunctionManager functionManager = program.getFunctionManager();

        List<Function> functions = new ArrayList<>();
        addFunctions(functions, functionManager.getFunctions(true));
        addFunctions(functions, functionManager.getExternalFunctions());

        for (Function function : functions) {
            monitor.checkCancelled();

            DataType returnBase = stripPointersAndArrays(function.getReturnType());
            if (isTrackedKind(returnBase)) {
                recordUsage(
                    discovered,
                    usagesByType,
                    pending,
                    returnBase,
                    new TypeUsageMetadata(
                        TypeUsageMetadata.KIND_FUNCTION_RETURN,
                        formatAddress(function.getEntryPoint()),
                        function.getName(),
                        null,
                        null,
                        null
                    )
                );
            }

            for (Parameter parameter : function.getParameters()) {
                DataType parameterBase = stripPointersAndArrays(parameter.getDataType());
                if (isTrackedKind(parameterBase)) {
                    recordUsage(
                        discovered,
                        usagesByType,
                        pending,
                        parameterBase,
                        new TypeUsageMetadata(
                            TypeUsageMetadata.KIND_FUNCTION_PARAMETER,
                            formatAddress(function.getEntryPoint()),
                            function.getName(),
                            parameter.getName(),
                            null,
                            null
                        )
                    );
                }
            }
        }
    }

    private static void collectGlobalDataUsages(
        Program program,
        TaskMonitor monitor,
        Map<TypeKey, DataType> discovered,
        Map<TypeKey, List<TypeUsageMetadata>> usagesByType,
        Deque<DataType> pending
    ) throws CancelledException {
        DataIterator definedData = program.getListing().getDefinedData(true);

        while (definedData.hasNext()) {
            monitor.checkCancelled();
            Data data = definedData.next();

            DataType dataBase = stripPointersAndArrays(data.getDataType());
            if (isTrackedKind(dataBase)) {
                recordUsage(
                    discovered,
                    usagesByType,
                    pending,
                    dataBase,
                    new TypeUsageMetadata(
                        TypeUsageMetadata.KIND_GLOBAL_DATA,
                        null,
                        null,
                        null,
                        formatAddress(data.getAddress()),
                        data.getLabel()
                    )
                );
            }
        }
    }

    // Struct/union fields and a typedef's target are added to the closure
    // (so their own fields/target get expanded in turn) but never get a
    // usage entry of their own -- that relationship is already visible
    // through the referencing type's `fields`/`targetTypeName`.
    private static void expandClosure(
        TaskMonitor monitor,
        Map<TypeKey, DataType> discovered,
        Deque<DataType> pending
    ) throws CancelledException {
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            DataType current = pending.poll();

            if (current instanceof Structure || current instanceof Union) {
                Composite composite = (Composite) current;

                for (DataTypeComponent component : composite.getComponents()) {
                    DataType fieldBase = stripPointersAndArrays(component.getDataType());

                    if (isTrackedKind(fieldBase)) {
                        discover(discovered, pending, fieldBase);
                    }
                }
            }
            else if (current instanceof TypeDef typeDef) {
                DataType targetBase = stripPointersAndArrays(typeDef.getDataType());

                if (isTrackedKind(targetBase)) {
                    discover(discovered, pending, targetBase);
                }
            }
            // Enum is a leaf: its values are plain integers, nothing to expand.
        }
    }

    private static void recordUsage(
        Map<TypeKey, DataType> discovered,
        Map<TypeKey, List<TypeUsageMetadata>> usagesByType,
        Deque<DataType> pending,
        DataType dataType,
        TypeUsageMetadata usage
    ) {
        TypeKey key = discover(discovered, pending, dataType);
        usagesByType.computeIfAbsent(key, unused -> new ArrayList<>()).add(usage);
    }

    // Registers a type in the closure the first time it's seen (so it gets
    // expanded exactly once, and self-referential/cyclic type graphs --
    // e.g. a linked-list node pointing at itself -- terminate correctly)
    // and returns its dedup key either way.
    private static TypeKey discover(
        Map<TypeKey, DataType> discovered,
        Deque<DataType> pending,
        DataType dataType
    ) {
        TypeKey key = TypeKey.of(dataType);

        if (discovered.putIfAbsent(key, dataType) == null) {
            pending.add(dataType);
        }

        return key;
    }

    private static DetectedTypeMetadata buildMetadata(
        DataType dataType,
        List<TypeUsageMetadata> usages
    ) {
        int length = dataType.getLength();
        Integer size = length > 0 ? length : null;
        boolean isAnonymous = dataType.getName().startsWith(ANONYMOUS_NAME_PREFIX);

        List<TypeFieldMetadata> fields = List.of();
        List<EnumValueMetadata> enumValues = List.of();
        String targetTypeName = null;
        String kind;

        if (dataType instanceof Structure || dataType instanceof Union) {
            kind = dataType instanceof Structure
                ? DetectedTypeMetadata.KIND_STRUCT
                : DetectedTypeMetadata.KIND_UNION;
            fields = collectFields((Composite) dataType);
        }
        else if (dataType instanceof Enum enumDataType) {
            kind = DetectedTypeMetadata.KIND_ENUM;
            enumValues = collectEnumValues(enumDataType);
        }
        else if (dataType instanceof TypeDef typeDef) {
            kind = DetectedTypeMetadata.KIND_TYPEDEF;
            targetTypeName = typeDef.getDataType().getName();
        }
        else {
            throw new IllegalStateException(
                "unexpected tracked data type kind: " + dataType.getClass()
            );
        }

        return new DetectedTypeMetadata(
            dataType.getName(),
            kind,
            dataType.getCategoryPath().getPath(),
            size,
            dataType.isNotYetDefined(),
            isAnonymous,
            fields,
            enumValues,
            targetTypeName,
            usages
        );
    }

    private static List<TypeFieldMetadata> collectFields(Composite composite) {
        List<TypeFieldMetadata> fields = new ArrayList<>(composite.getNumComponents());

        for (DataTypeComponent component : composite.getComponents()) {
            fields.add(new TypeFieldMetadata(
                component.getFieldName(),
                component.getDataType().getName(),
                component.getOffset()
            ));
        }

        return fields;
    }

    private static List<EnumValueMetadata> collectEnumValues(Enum enumDataType) {
        String[] names = enumDataType.getNames();
        List<EnumValueMetadata> values = new ArrayList<>(names.length);

        for (String name : names) {
            values.add(new EnumValueMetadata(name, enumDataType.getValue(name)));
        }

        return values;
    }

    private static boolean isTrackedKind(DataType dataType) {
        return dataType instanceof Structure
            || dataType instanceof Union
            || dataType instanceof Enum
            || dataType instanceof TypeDef;
    }

    // Unwraps pointer/array layers only -- a Typedef/Structure/Union/Enum is
    // itself one of the tracked kinds and must stop the unwrap so it becomes
    // its own closure entry rather than being silently skipped through.
    private static DataType stripPointersAndArrays(DataType dataType) {
        DataType current = dataType;

        while (current != null) {
            if (current instanceof Pointer pointer) {
                current = pointer.getDataType();
            }
            else if (current instanceof Array array) {
                current = array.getDataType();
            }
            else {
                break;
            }
        }

        return current;
    }

    private static void addFunctions(
        List<Function> destination,
        FunctionIterator iterator
    ) {
        while (iterator.hasNext()) {
            destination.add(iterator.next());
        }
    }

    private static String formatAddress(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private record TypeKey(String category, String name) {

        static TypeKey of(DataType dataType) {
            return new TypeKey(dataType.getCategoryPath().getPath(), dataType.getName());
        }
    }
}
