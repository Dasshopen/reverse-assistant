package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class BsimBulkQueryService {

    // Ghidra's local H2 BSim backend can return an incomplete nearest-neighbour
    // response when a query contains too many generated signatures.  The corpus
    // verifier already uses batches of 25 for this reason; keep the production
    // bulk scan on the same proven bound so named matches are not silently lost.
    private static final int BATCH_SIZE = 25;
    private static final int MAX_COMBINED_MATCHES = 12;

    private final BsimFunctionQueryService queryService = new BsimFunctionQueryService();

    public List<BsimBulkFunctionResult> query(
        Program program,
        List<Function> functions,
        List<BsimCorpus> corpora,
        TaskMonitor monitor
    ) throws CancelledException {
        Map<Long, List<BsimCandidate>> matchesByAddress = new LinkedHashMap<>();
        for (Function function : functions) {
            matchesByAddress.put(function.getEntryPoint().getOffset(), new ArrayList<>());
        }

        List<String> failures = new ArrayList<>();
        Set<Long> scannedAddresses = new HashSet<>();

        for (BsimCorpus corpus : corpora) {
            boolean corpusFailed = false;
            for (int start = 0; start < functions.size(); start += BATCH_SIZE) {
                int end = Math.min(start + BATCH_SIZE, functions.size());
                try {
                    Map<Long, List<BsimCandidate>> batch = queryService.queryBatch(
                        program,
                        functions.subList(start, end),
                        corpus.name(),
                        corpus.databaseUrl(),
                        monitor
                    );
                    for (Map.Entry<Long, List<BsimCandidate>> entry : batch.entrySet()) {
                        matchesByAddress
                            .computeIfAbsent(entry.getKey(), ignored -> new ArrayList<>())
                            .addAll(entry.getValue());
                    }
                    for (Function function : functions.subList(start, end)) {
                        scannedAddresses.add(function.getEntryPoint().getOffset());
                    }
                }
                catch (CancelledException exception) {
                    throw exception;
                }
                catch (Exception exception) {
                    failures.add(corpus.name() + ": " + exception.getMessage());
                    corpusFailed = true;
                    break;
                }
            }
            if (corpusFailed) {
                continue;
            }
        }

        String message = failures.isEmpty()
            ? null
            : "Some BSim corpora could not be queried: " + String.join(" | ", failures);
        Comparator<BsimCandidate> ranking = Comparator
            .comparingDouble(BsimCandidate::similarity)
            .thenComparingDouble(BsimCandidate::significance)
            .reversed();

        List<BsimBulkFunctionResult> results = new ArrayList<>();
        for (Function function : functions) {
            List<BsimCandidate> candidates = matchesByAddress.get(function.getEntryPoint().getOffset());
            candidates.sort(ranking);
            if (candidates.size() > MAX_COMBINED_MATCHES) {
                candidates = new ArrayList<>(candidates.subList(0, MAX_COMBINED_MATCHES));
            }
            results.add(new BsimBulkFunctionResult(
                "0x" + Long.toUnsignedString(
                    function.getEntryPoint().getOffset(),
                    16
                ),
                candidates,
                scannedAddresses.contains(function.getEntryPoint().getOffset()),
                message
            ));
        }
        return results;
    }
}
