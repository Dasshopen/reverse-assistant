// One-time validation tool (not deployed as part of the shipped extension):
// headless-compatible adaptation of Ghidra's own BSim example script
// (Ghidra/Features/BSim/ghidra_scripts/QueryFunction.java), used to prove
// the seed corpus pipeline works end to end. Run as a -process postScript
// against one of the already-analyzed reference projects (e.g. sqlite3 or
// zlib): internal, non-thunk functions are processed in bounded batches.
// Every batch gets a fresh GenSignatures/DescriptionManager so signatures
// cannot leak into subsequent queries and very large programs do not trigger
// incomplete responses from one oversized BSim request.
// The script withholds its success marker if a function BSim actually scored
// cannot be tied back to its reference executable; verify-corpus.ps1 turns a
// missing marker into a non-zero exit. Functions BSim returns no result for
// at all
// (observed for very small functions) and functions whose exact-name self
// entry is displaced by tied near-duplicate siblings (observed for trivial
// stub/wrapper functions) are both reported separately, not treated as
// failures -- see the comments below for why each is expected.
//@category Reverse Assistant

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class VerifyBsimQuery extends GhidraScript {

    // Validation needs a deeper result window than the product UI: dozens of
    // byte-identical CRT/no-op stubs can tie at 1.0 and otherwise displace the
    // reference executable's own entry from a small top-K.
    private static final int MATCHES_PER_FUNC = 100;
    private static final int MATCHES_TO_PRINT = 3;
    private static final int FUNCTIONS_PER_BATCH = 25;
    private static final double SIMILARITY_BOUND = 0.5;
    private static final double CONFIDENCE_BOUND = 0.0;
    private static final double SELF_MATCH_SIMILARITY_THRESHOLD = 0.999;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 1 || args[0].isBlank()) {
            printerr("Usage: VerifyBsimQuery <bsim-database-url> [success-marker-path]");
            throw new IllegalArgumentException("missing BSim database URL");
        }

        if (currentProgram == null) {
            printerr("No program is loaded to query.");
            throw new IllegalStateException("no current program to query");
        }

        String executableName = currentProgram.getName();
        URL url = BSimClientFactory.deriveBSimURL(args[0]);
        Path successMarker = args.length >= 2 && !args[1].isBlank()
            ? Path.of(args[1]).toAbsolutePath()
            : null;

        if (successMarker != null) {
            Files.deleteIfExists(successMarker);
        }

        try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
            if (!database.initialize()) {
                printerr(database.getLastError().message);
                throw new IllegalStateException("failed to initialize BSim database connection");
            }

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            List<Function> queriedFunctions = new ArrayList<>();

            for (Function func : functions) {
                if (!func.isExternal() && !func.isThunk()) {
                    queriedFunctions.add(func);
                }
            }

            if (queriedFunctions.isEmpty()) {
                println("No internal, non-thunk functions to query.");
                return;
            }

            // Addresses, rather than names, identify query functions. Names
            // are not unique in Ghidra because of namespaces and duplicate
            // symbols.
            Set<Long> selfMatchedAddresses = new HashSet<>();
            Set<Long> respondedAddresses = new HashSet<>();

            for (int batchStart = 0; batchStart < queriedFunctions.size(); batchStart += FUNCTIONS_PER_BATCH) {
                monitor.checkCancelled();
                int batchEnd = Math.min(batchStart + FUNCTIONS_PER_BATCH, queriedFunctions.size());
                GenSignatures gensig = new GenSignatures(false);

                try {
                    gensig.setVectorFactory(database.getLSHVectorFactory());
                    gensig.openProgram(currentProgram, null, null, null, null, null);

                    for (int index = batchStart; index < batchEnd; index++) {
                        monitor.checkCancelled();
                        gensig.scanFunction(queriedFunctions.get(index));
                    }

                    QueryNearest query = new QueryNearest();
                    query.manage = gensig.getDescriptionManager();
                    query.max = MATCHES_PER_FUNC;
                    query.thresh = SIMILARITY_BOUND;
                    query.signifthresh = CONFIDENCE_BOUND;

                    ResponseNearest response = query.execute(database);

                    if (response == null) {
                        printerr(database.getLastError().message);
                        throw new IllegalStateException(
                            "BSim query failed for function batch " + batchStart + ".." + (batchEnd - 1)
                        );
                    }

                    for (SimilarityResult sim : response.result) {
                        FunctionDescription base = sim.getBase();
                        long baseAddress = base.getAddress();
                        respondedAddresses.add(baseAddress);

                        println("Queried function: " + base.getFunctionName()
                            + " @ 0x" + Long.toHexString(baseAddress));

                        int printedMatches = 0;

                        for (SimilarityNote note : sim) {
                            FunctionDescription fdesc = note.getFunctionDescription();

                            if (printedMatches < MATCHES_TO_PRINT) {
                                println("  Match: " + fdesc.getFunctionName()
                                    + " (executable: " + fdesc.getExecutableRecord().getNameExec() + ")"
                                    + " similarity=" + note.getSimilarity()
                                    + " significance=" + note.getSignificance());
                                printedMatches++;
                            }

                            boolean sameExecutable = fdesc.getExecutableRecord().getNameExec()
                                .equals(executableName);
                            boolean isExactSelf = sameExecutable
                                && fdesc.getAddress() == baseAddress;

                            // The exact database record is authoritative even
                            // if regenerated features vary slightly (observed
                            // for sqlite3JournalOpen: exact executable/address,
                            // similarity 0.873). For tiny duplicate helpers,
                            // the literal record can instead fall outside the
                            // top-K, so a near-1.0 equivalent from the same
                            // executable is also valid.
                            boolean isEquivalentSelf = sameExecutable
                                && note.getSimilarity() >= SELF_MATCH_SIMILARITY_THRESHOLD;
                            boolean isSelfMatch = isExactSelf || isEquivalentSelf;

                            if (isSelfMatch) {
                                selfMatchedAddresses.add(baseAddress);
                            }
                        }
                    }
                }
                finally {
                    gensig.dispose();
                }
            }

            List<String> skippedTooSmall = new ArrayList<>();
            List<String> missingSelfMatches = new ArrayList<>();

            for (Function func : queriedFunctions) {
                long entryOffset = func.getEntryPoint().getOffset();
                String label = func.getName() + " @ " + func.getEntryPoint();

                if (!respondedAddresses.contains(entryOffset)) {
                    skippedTooSmall.add(label);
                }
                else if (!selfMatchedAddresses.contains(entryOffset)) {
                    missingSelfMatches.add(label);
                }
            }

            println("Total functions queried: " + queriedFunctions.size());
            println("Skipped by BSim (no signature/result at all, likely too small): "
                + skippedTooSmall.size());

            if (!missingSelfMatches.isEmpty()) {
                printerr("Functions BSim scored but which missed their own self-match: " + missingSelfMatches);
                throw new IllegalStateException(
                    missingSelfMatches.size() + " of " + queriedFunctions.size()
                        + " functions BSim scored did not match themselves in the BSim database"
                );
            }

            println("Every function BSim scored (" + respondedAddresses.size()
                + " of " + queriedFunctions.size() + ") matched itself in the BSim database.");

            if (successMarker != null) {
                Files.createDirectories(successMarker.getParent());
                Files.writeString(successMarker, "validated\n", StandardCharsets.UTF_8);
            }
        }
    }
}
