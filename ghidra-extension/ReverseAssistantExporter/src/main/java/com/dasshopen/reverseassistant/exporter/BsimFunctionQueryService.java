package com.dasshopen.reverseassistant.exporter;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    // Ask the database for more than the UI ultimately retains. Large
    // corpora can contain several byte-identical unnamed helpers; filtering
    // those placeholders after a top-5 query would otherwise hide a useful
    // named match ranked just below them.
    private static final int MATCHES_PER_FUNCTION = 25;
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

        Map<Long, List<BsimCandidate>> matches = queryBatch(
            program,
            List.of(function),
            corpus,
            databaseUrl,
            monitor
        );
        return BsimQueryResult.available(
            matches.getOrDefault(function.getEntryPoint().getOffset(), List.of())
        );
    }

    public Map<Long, List<BsimCandidate>> queryBatch(
        Program program,
        Collection<Function> functions,
        String corpus,
        String databaseUrl,
        TaskMonitor monitor
    ) throws Exception {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(functions, "functions must not be null");
        Objects.requireNonNull(corpus, "corpus must not be null");
        Objects.requireNonNull(databaseUrl, "databaseUrl must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        Map<Long, List<BsimCandidate>> candidatesByAddress = new LinkedHashMap<>();
        for (Function function : functions) {
            candidatesByAddress.put(function.getEntryPoint().getOffset(), new ArrayList<>());
        }

        URL url = BSimClientFactory.deriveBSimURL(databaseUrl);

        try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
            if (!database.initialize()) {
                throw new IllegalStateException(database.getLastError().message);
            }

            GenSignatures signatures = new GenSignatures(false);

            try {
                signatures.setVectorFactory(database.getLSHVectorFactory());
                signatures.openProgram(program, null, null, null, null, null);
                for (Function function : functions) {
                    signatures.scanFunction(function);
                    monitor.checkCancelled();
                }
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

                for (SimilarityResult similarityResult : response.result) {
                    List<BsimCandidate> candidates = candidatesByAddress.computeIfAbsent(
                        similarityResult.getBase().getAddress(),
                        ignored -> new ArrayList<>()
                    );
                    for (SimilarityNote note : similarityResult) {
                        FunctionDescription match = note.getFunctionDescription();

                        if (!isMeaningfulCandidateName(match.getFunctionName())) {
                            continue;
                        }

                        candidates.add(new BsimCandidate(
                            match.getFunctionName(),
                            match.getExecutableRecord().getNameExec(),
                            corpus,
                            note.getSimilarity(),
                            note.getSignificance()
                        ));
                    }
                }

                return candidatesByAddress;
            }
            catch (CancelledException exception) {
                throw exception;
            }
            finally {
                signatures.dispose();
            }
        }
    }

    static boolean isMeaningfulCandidateName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }

        return !name.matches("(?i)^(?:thunk_)?FUN_[0-9a-f]+$")
            && !name.matches("(?i)^sub_[0-9a-f]+$")
            && !name.matches("(?i)^LAB_[0-9a-f]+$")
            && !name.startsWith("??_C@");
    }
}
