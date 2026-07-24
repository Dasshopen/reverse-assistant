package com.dasshopen.reverseassistant.exporter;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class BsimFunctionQueryService {

    private static final int MATCHES_PER_FUNCTION = 5;
    private static final double SIMILARITY_THRESHOLD = 0.7;
    private static final double SIGNIFICANCE_THRESHOLD = 0.0;

    public BsimQueryResult query(
        Program program,
        Function function,
        String corpus,
        String databaseUrl,
        TaskMonitor monitor
    ) throws Exception {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(function, "function must not be null");
        Objects.requireNonNull(corpus, "corpus must not be null");
        Objects.requireNonNull(databaseUrl, "databaseUrl must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        URL url = BSimClientFactory.deriveBSimURL(databaseUrl);

        try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
            if (!database.initialize()) {
                throw new IllegalStateException(database.getLastError().message);
            }

            GenSignatures signatures = new GenSignatures(false);

            try {
                signatures.setVectorFactory(database.getLSHVectorFactory());
                signatures.openProgram(program, null, null, null, null, null);
                signatures.scanFunction(function);
                monitor.checkCancelled();

                DescriptionManager manager = signatures.getDescriptionManager();
                QueryNearest query = new QueryNearest();
                query.manage = manager;
                query.max = MATCHES_PER_FUNCTION;
                query.thresh = SIMILARITY_THRESHOLD;
                query.signifthresh = SIGNIFICANCE_THRESHOLD;

                ResponseNearest response = query.execute(database);

                if (response == null) {
                    throw new IllegalStateException(database.getLastError().message);
                }

                List<BsimCandidate> candidates = new ArrayList<>();

                for (SimilarityResult similarityResult : response.result) {
                    for (SimilarityNote note : similarityResult) {
                        FunctionDescription match = note.getFunctionDescription();

                        candidates.add(new BsimCandidate(
                            match.getFunctionName(),
                            match.getExecutableRecord().getNameExec(),
                            corpus,
                            note.getSimilarity(),
                            note.getSignificance()
                        ));
                    }
                }

                return BsimQueryResult.available(candidates);
            }
            catch (CancelledException exception) {
                throw exception;
            }
            finally {
                signatures.dispose();
            }
        }
    }
}
