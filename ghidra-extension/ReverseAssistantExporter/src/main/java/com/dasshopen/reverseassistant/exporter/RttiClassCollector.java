package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// Recovers the real C++ class name(s) a function actually serves, straight
// from the binary's own MSVC RTTI metadata -- never a guess. When the
// compiler/linker folds several classes' trivial destructors into one
// byte-identical function (extremely common for exception hierarchies:
// std::bad_alloc, std::out_of_range, etc. compile to the same "scalar
// deleting destructor" when they add no members of their own),
// FunctionID/BSim can only report a large, noisy list of same-shaped
// library candidates. The class's real vtable, however, still points at
// this exact function, and every vtable is preceded by a pointer to its
// RTTICompleteObjectLocator, which in turn points to a TypeDescriptor
// holding the real mangled class name -- data, not code, so it survives
// the fold. Walking that chain gives the exact, verifiable set of real
// classes a function serves, however many there are.
//
// Windows/MSVC-specific: this relies on the native RTTI layout Ghidra's
// own analysis already recognizes (RTTICompleteObjectLocator/
// TypeDescriptor as real Ghidra data types). Never fabricated when this
// data is absent (non-MSVC binaries, or RTTI disabled) -- functions
// simply get no entry.
public final class RttiClassCollector {

    private static final String LOCATOR_TYPE_NAME = "RTTICompleteObjectLocator";
    private static final int MAX_BACKWARD_SLOTS = 3;
    private static final long SLOT_SIZE_BYTES = 8L;

    private RttiClassCollector() {
    }

    // Maps a function's entry address (formatted the same way as every
    // other address in this exporter) to the sorted, deduplicated list of
    // real class names whose vtable references it.
    public static Map<String, List<String>> collectClassNamesByFunctionAddress(
        Program program,
        TaskMonitor monitor
    ) throws CancelledException {
        Objects.requireNonNull(program, "program must not be null");

        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager referenceManager = program.getReferenceManager();

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = functionManager.getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (!function.isExternal()) {
                functions.add(function);
            }
        }

        monitor.initialize(functions.size(), "Resolving RTTI class references");

        Map<String, LinkedHashSet<String>> classNamesByAddress = new LinkedHashMap<>();

        for (Function function : functions) {
            monitor.checkCancelled();
            monitor.increment();

            ReferenceIterator refs = referenceManager.getReferencesTo(function.getEntryPoint());
            while (refs.hasNext()) {
                Reference reference = refs.next();
                String className = findNearbyClassName(program, reference.getFromAddress());
                if (className != null) {
                    classNamesByAddress
                        .computeIfAbsent(formatAddress(function), key -> new LinkedHashSet<>())
                        .add(className);
                }
            }
        }

        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, LinkedHashSet<String>> entry : classNamesByAddress.entrySet()) {
            List<String> sorted = new ArrayList<>(entry.getValue());
            Collections.sort(sorted);
            result.put(entry.getKey(), List.copyOf(sorted));
        }
        return result;
    }

    // MSVC vtable layout places a pointer to the class's
    // RTTICompleteObjectLocator immediately before the vtable's first
    // (slot 0) function pointer. A polymorphic function pointer found in a
    // vtable is very often that first slot (the destructor), but a bounded
    // backward search covers a few slots further in without risking an
    // unbounded/incorrect walk.
    private static String findNearbyClassName(Program program, Address vtableSlot) {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();

        for (int back = 1; back <= MAX_BACKWARD_SLOTS; back++) {
            Address candidate;
            long rawValue;
            try {
                candidate = vtableSlot.subtract(back * SLOT_SIZE_BYTES);
                rawValue = memory.getLong(candidate);
            } catch (MemoryAccessException | AddressOutOfBoundsException exception) {
                break;
            }

            Address locatorAddress = toProgramAddress(program, rawValue);
            if (locatorAddress == null) {
                continue;
            }

            Data data = listing.getDefinedDataAt(locatorAddress);
            if (data == null || !LOCATOR_TYPE_NAME.equals(data.getDataType().getName())) {
                continue;
            }

            String className = resolveClassName(program, locatorAddress);
            if (className != null) {
                return className;
            }
        }

        return null;
    }

    // RTTICompleteObjectLocator (x64): signature(4), offset(4), cdOffset(4),
    // pTypeDescriptor(4, image-base-relative), pClassDescriptor(4,
    // image-base-relative), pSelf(4, image-base-relative).
    private static String resolveClassName(Program program, Address locatorAddress) {
        try {
            Memory memory = program.getMemory();
            int typeDescriptorRelative = memory.getInt(locatorAddress.add(12));
            long imageBase = program.getImageBase().getOffset();
            Address typeDescriptorAddress =
                toProgramAddress(program, imageBase + (typeDescriptorRelative & 0xFFFFFFFFL));
            if (typeDescriptorAddress == null) {
                return null;
            }

            String mangledName = readNullTerminatedString(memory, typeDescriptorAddress.add(16));
            return demangleTypeDescriptorName(mangledName);
        } catch (MemoryAccessException | AddressOutOfBoundsException exception) {
            return null;
        }
    }

    private static String readNullTerminatedString(Memory memory, Address start)
        throws MemoryAccessException {
        StringBuilder builder = new StringBuilder();
        Address current = start;
        for (int i = 0; i < 300; i++) {
            byte value = memory.getByte(current);
            if (value == 0) {
                break;
            }
            builder.append((char) (value & 0xFF));
            current = current.add(1);
        }
        return builder.toString();
    }

    // MSVC RTTI TypeDescriptor names use a simple mangled form:
    // ".?A[V|U]<name>@<enclosing>@...@@" (namespaces innermost-first,
    // terminated by "@@"; a name with no enclosing namespace has no
    // intermediate "@" segments at all). This is not general name
    // demangling -- only this one specific, well-documented shape.
    private static String demangleTypeDescriptorName(String rawName) {
        if (rawName == null || !rawName.startsWith(".?A") || rawName.length() < 4) {
            return null;
        }

        String afterKind = rawName.substring(4);
        if (!afterKind.endsWith("@@")) {
            return null;
        }

        String body = afterKind.substring(0, afterKind.length() - 2);
        if (body.isEmpty()) {
            return null;
        }

        List<String> segments = new ArrayList<>(List.of(body.split("@")));
        Collections.reverse(segments);
        return String.join("::", segments);
    }

    private static Address toProgramAddress(Program program, long offset) {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (Exception exception) {
            return null;
        }
    }

    private static String formatAddress(Function function) {
        return "0x" + Long.toUnsignedString(function.getEntryPoint().getOffset(), 16);
    }
}
