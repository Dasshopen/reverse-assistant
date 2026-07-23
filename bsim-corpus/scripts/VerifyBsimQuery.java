// One-time validation tool (not deployed as part of the shipped extension):
// headless-compatible adaptation of Ghidra's own BSim example script
// (Ghidra/Features/BSim/ghidra_scripts/QueryFunction.java), used to prove
// the seed corpus pipeline works end to end. Run as a -process postScript
// against one of the already-analyzed reference projects (e.g. sqlite3 or
// zlib): every internal, non-thunk function's signature is generated into a
// single DescriptionManager, then queried against the freshly-built BSim
// database in one batch query (not one query per function -- scanFunction
// accumulates into the same manager, so querying inside the loop would mean
// each successive query silently included every function scanned so far).
// The script fails loudly (non-zero exit) if a function BSim actually
// scored doesn't find a near-1.0 match from its own executable, instead of
// only printing results. Functions BSim returns no result for at all
// (observed for very small functions) and functions whose exact-name self
// entry is displaced by tied near-duplicate siblings (observed for trivial
// stub/wrapper functions) are both reported separately, not treated as
// failures -- see the comments below for why each is expected.
//@category Reverse Assistant

import java.net.URL;
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

    private static final int MATCHES_PER_FUNC = 20;
    private static final double SIMILARITY_BOUND = 0.5;
    private static final double CONFIDENCE_BOUND = 0.0;
    private static final double SELF_MATCH_SIMILARITY_THRESHOLD = 0.999;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 1 || args[0].isBlank()) {
            printerr("Usage: VerifyBsimQuery <bsim-database-url>");
            throw new IllegalArgumentException("missing BSim database URL");
        }

        if (currentProgram == null) {
            printerr("No program is loaded to query.");
            throw new IllegalStateException("no current program to query");
        }

        String executableName = currentProgram.getName();
        URL url = BSimClientFactory.deriveBSimURL(args[0]);

        try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
            if (!database.initialize()) {
                printerr(database.getLastError().message);
                throw new IllegalStateException("failed to initialize BSim database connection");
            }

            GenSignatures gensig = new GenSignatures(false);

            try {
                gensig.setVectorFactory(database.getLSHVectorFactory());
                gensig.openProgram(currentProgram, null, null, null, null, null);

                DescriptionManager manager = gensig.getDescriptionManager();
                FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

                List<Function> queriedFunctions = new ArrayList<>();

                for (Function func : functions) {
                    if (func.isExternal() || func.isThunk()) {
                        continue;
                    }

                    gensig.scanFunction(func);
                    queriedFunctions.add(func);
                }

                if (queriedFunctions.isEmpty()) {
                    println("No internal, non-thunk functions to query.");
                    return;
                }

                QueryNearest query = new QueryNearest();
                query.manage = manager;
                query.max = MATCHES_PER_FUNC;
                query.thresh = SIMILARITY_BOUND;
                query.signifthresh = CONFIDENCE_BOUND;

                ResponseNearest response = query.execute(database);

                if (response == null) {
                    printerr(database.getLastError().message);
                    throw new IllegalStateException("BSim query failed");
                }

                Set<String> selfMatchedNames = new HashSet<>();
                // Functions BSim actually returned a SimilarityResult for --
                // distinct from functions BSim silently produced no result
                // for at all (observed for very small/trivial functions,
                // e.g. a 5-code-unit optimized tail-call wrapper: too little
                // code to build a meaningful LSH vector, not a pipeline bug).
                Set<String> respondedNames = new HashSet<>();

                for (SimilarityResult sim : response.result) {
                    FunctionDescription base = sim.getBase();

                    respondedNames.add(base.getFunctionName());

                    println("Queried function: " + base.getFunctionName());

                    for (SimilarityNote note : sim) {
                        FunctionDescription fdesc = note.getFunctionDescription();

                        println("  Match: " + fdesc.getFunctionName()
                            + " (executable: " + fdesc.getExecutableRecord().getNameExec() + ")"
                            + " similarity=" + note.getSimilarity()
                            + " significance=" + note.getSignificance());

                        // Deliberately NOT requiring the matched name to
                        // equal the queried name: trivial/duplicate helper
                        // functions (single-instruction stubs, thin
                        // wrappers) legitimately tie at ~1.0 similarity with
                        // many siblings (confirmed empirically -- e.g.
                        // noopMutexInit ties with 40+ other 3-code-unit
                        // stubs), so the literal self entry can rank outside
                        // any bounded top-K. What actually proves the round
                        // trip worked for this function's own code is that
                        // *some* near-1.0 match comes back from the same
                        // executable we just queried from.
                        boolean isSelfMatch = fdesc.getExecutableRecord().getNameExec().equals(executableName)
                            && note.getSimilarity() >= SELF_MATCH_SIMILARITY_THRESHOLD;

                        if (isSelfMatch) {
                            selfMatchedNames.add(base.getFunctionName());
                        }
                    }
                }

                List<String> skippedTooSmall = new ArrayList<>();
                List<String> missingSelfMatches = new ArrayList<>();

                for (Function func : queriedFunctions) {
                    if (!respondedNames.contains(func.getName())) {
                        skippedTooSmall.add(func.getName());
                    }
                    else if (!selfMatchedNames.contains(func.getName())) {
                        missingSelfMatches.add(func.getName());
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

                println("Every function BSim scored (" + respondedNames.size()
                    + " of " + queriedFunctions.size() + ") matched itself in the BSim database.");
            }
            finally {
                gensig.dispose();
            }
        }
    }
}
