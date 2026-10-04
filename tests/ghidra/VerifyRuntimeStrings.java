// Read-only regression check against a real Ghidra program.
// Run with -readOnly -noanalysis -postScript VerifyRuntimeStrings.java [minimum-excluded].
//@category Reverse Assistant Tests

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.dasshopen.reverseassistant.exporter.GlobalStringMetadata;
import com.dasshopen.reverseassistant.exporter.ProgramStringsCollector;
import com.dasshopen.reverseassistant.exporter.StringReferenceMetadata;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.ReferenceIterator;

public class VerifyRuntimeStrings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Set<String> expected = new HashSet<>();
        int excluded = 0;
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext()) {
            monitor.checkCancelled();
            Data item = data.next();
            if (!item.hasStringValue() || !(item.getValue() instanceof String)) {
                continue;
            }
            ReferenceIterator references = currentProgram.getReferenceManager()
                .getReferencesTo(item.getAddress());
            if (!item.getAddress().isLoadedMemoryAddress()) {
                if (references.hasNext()) {
                    excluded++;
                }
                continue;
            }
            while (references.hasNext()) {
                if (references.next().getFromAddress().isLoadedMemoryAddress()) {
                    expected.add(formatAddress(item.getAddress()));
                }
            }
        }

        List<GlobalStringMetadata> result = new ProgramStringsCollector()
            .collect(currentProgram, monitor);
        Set<String> actual = new HashSet<>();
        for (GlobalStringMetadata string : result) {
            require(actual.add(string.address()), "duplicate runtime string: " + string.address());
            require(!string.references().isEmpty(), "unreferenced runtime string");
            for (StringReferenceMetadata reference : string.references()) {
                require(currentProgram.getMemory().contains(
                    toAddr(reference.instructionAddress())), "reference outside runtime memory");
            }
        }
        require(actual.equals(expected), "runtime strings were lost or metadata leaked into export");
        require(!actual.isEmpty(), "test needs at least one referenced runtime string");
        String[] args = getScriptArgs();
        int minimumExcluded = args.length == 0 ? 0 : Integer.parseInt(args[0]);
        require(excluded >= minimumExcluded, "test lacks non-loaded metadata regression cases");
        println("PASS runtime strings: " + result.size() + " retained, " + excluded
            + " referenced non-loaded metadata strings excluded");
    }

    private static String formatAddress(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
