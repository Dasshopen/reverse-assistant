package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// Global, whole-program view of "strings actually used": every defined
// string constant that has at least one real Ghidra reference to it, with
// every referencing instruction and its containing function (if any).
// Unlike FunctionMetadataCollector's removed per-function string list, this
// uses ReferenceManager.getReferencesTo so the reference count reflects
// every instruction that touches the string, even multiple times from the
// same function -- not just "does this function use it at all".
public final class ProgramStringsCollector {

    public List<GlobalStringMetadata> collect(
        Program program,
        TaskMonitor monitor
    ) throws CancelledException {
        Listing listing = program.getListing();
        ReferenceManager referenceManager = program.getReferenceManager();

        List<Data> stringData = new ArrayList<>();
        DataIterator definedData = listing.getDefinedData(true);

        while (definedData.hasNext()) {
            monitor.checkCancelled();
            Data data = definedData.next();

            // ELF debug/comment sections can live in separate, non-loaded
            // address spaces, each starting at offset zero. They are metadata,
            // not runtime strings. The wire format carries virtual addresses,
            // so flattening those spaces to an offset would invent collisions.
            if (data.getAddress().isLoadedMemoryAddress() && data.hasStringValue()) {
                stringData.add(data);
            }
        }

        // Addresses are compared by their unsigned numeric offset, not the
        // formatted "0x..." string -- lexicographic comparison would put
        // "0x10" before "0x9". Sorting happens before formatting so both
        // levels (strings, and references within a string) end up correctly
        // ordered by address.
        stringData.sort(Comparator.comparingLong(data -> data.getAddress().getOffset()));

        monitor.initialize(stringData.size(), "Collecting referenced strings");

        List<GlobalStringMetadata> strings = new ArrayList<>();

        for (Data data : stringData) {
            monitor.checkCancelled();
            monitor.increment();

            Object value = data.getValue();

            if (!(value instanceof String stringValue)) {
                continue;
            }

            ReferenceIterator references = referenceManager.getReferencesTo(data.getAddress());
            List<Reference> sortedReferences = new ArrayList<>();

            while (references.hasNext()) {
                Reference reference = references.next();
                // Do not turn debug-section references into code addresses or
                // use them as semantic evidence for the naming agent.
                if (reference.getFromAddress().isLoadedMemoryAddress()) {
                    sortedReferences.add(reference);
                }
            }

            if (sortedReferences.isEmpty()) {
                continue;
            }

            sortedReferences.sort(
                Comparator.comparingLong(reference -> reference.getFromAddress().getOffset())
            );

            List<StringReferenceMetadata> referenceMetadata =
                new ArrayList<>(sortedReferences.size());

            for (Reference reference : sortedReferences) {
                Address fromAddress = reference.getFromAddress();
                Function containingFunction = program.getFunctionManager()
                    .getFunctionContaining(fromAddress);

                referenceMetadata.add(new StringReferenceMetadata(
                    formatAddress(fromAddress),
                    containingFunction == null
                        ? null
                        : formatAddress(containingFunction.getEntryPoint())
                ));
            }

            strings.add(new GlobalStringMetadata(
                formatAddress(data.getAddress()),
                stringValue,
                referenceMetadata
            ));
        }

        return List.copyOf(strings);
    }

    private static String formatAddress(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }
}
