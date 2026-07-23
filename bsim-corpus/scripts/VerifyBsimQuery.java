// One-time validation tool (not deployed as part of the shipped extension):
// headless-compatible adaptation of Ghidra's own BSim example script
// (Ghidra/Features/BSim/ghidra_scripts/QueryFunction.java), used to prove
// the seed corpus pipeline works end to end. Run as a -process postScript
// against one of the already-analyzed reference projects (e.g. zlib):
// every internal, non-thunk function is queried against the freshly-built
// BSim database, and matches are printed. A working pipeline should match
// each function back to its own executable with high similarity.
//@category Reverse Assistant

import java.net.URL;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class VerifyBsimQuery extends GhidraScript {

    private static final int MATCHES_PER_FUNC = 5;
    private static final double SIMILARITY_BOUND = 0.5;
    private static final double CONFIDENCE_BOUND = 0.0;

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

                FunctionIterator functions =
                    currentProgram.getFunctionManager().getFunctions(true);

                int queried = 0;

                for (Function func : functions) {
                    if (func.isExternal() || func.isThunk()) {
                        continue;
                    }

                    DescriptionManager manager = gensig.getDescriptionManager();

                    gensig.scanFunction(func);

                    QueryNearest query = new QueryNearest();
                    query.manage = manager;
                    query.max = MATCHES_PER_FUNC;
                    query.thresh = SIMILARITY_BOUND;
                    query.signifthresh = CONFIDENCE_BOUND;

                    ResponseNearest response = query.execute(database);

                    if (response == null) {
                        printerr(database.getLastError().message);
                        continue;
                    }

                    queried++;

                    println("Queried function: " + func.getName() + " (" + func.getEntryPoint() + ")");

                    Iterator<SimilarityResult> iter = response.result.iterator();

                    while (iter.hasNext()) {
                        SimilarityResult sim = iter.next();
                        Iterator<SimilarityNote> subiter = sim.iterator();

                        while (subiter.hasNext()) {
                            SimilarityNote note = subiter.next();
                            FunctionDescription fdesc = note.getFunctionDescription();

                            println("  Match: " + fdesc.getFunctionName()
                                + " (executable: " + fdesc.getExecutableRecord().getNameExec() + ")"
                                + " similarity=" + note.getSimilarity()
                                + " significance=" + note.getSignificance());
                        }
                    }
                }

                println("Total functions queried: " + queried);
            }
            finally {
                gensig.dispose();
            }
        }
    }
}
