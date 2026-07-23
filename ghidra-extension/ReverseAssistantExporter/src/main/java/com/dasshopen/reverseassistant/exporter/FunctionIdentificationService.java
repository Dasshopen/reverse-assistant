package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.service.FidMatch;
import ghidra.feature.fid.service.FidProgramSeeker;
import ghidra.feature.fid.service.FidSearchResult;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

// Identifies known library functions using Ghidra's built-in FunctionID (FID)
// feature. Confirmed (by reading the shipped FID source) to be a genuinely
// per-function operation: FidProgramSeeker only hashes code units and looks
// at direct callers/callees, it never invokes the decompiler, so this is safe
// to run as part of the same headless invocation as the main export instead
// of needing a separate on-demand round trip.
public final class FunctionIdentificationService {

    private final FunctionIdentificationJsonWriter jsonWriter;
    private final AtomicUtf8FileWriter fileWriter;

    public FunctionIdentificationService() {
        jsonWriter = new FunctionIdentificationJsonWriter();
        fileWriter = new AtomicUtf8FileWriter();
    }

    public void identifyAndWrite(
        Program program,
        Path destination,
        TaskMonitor monitor
    ) throws IOException, CancelledException, VersionException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(destination, "destination must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        List<FunctionIdentification> identifications = identify(program, monitor);

        fileWriter.write(destination, jsonWriter.write(identifications));
    }

    private List<FunctionIdentification> identify(
        Program program,
        TaskMonitor monitor
    ) throws IOException, CancelledException, VersionException {
        FidService fidService = new FidService();

        if (!fidService.canProcess(program.getLanguage())) {
            return List.of();
        }

        try (FidQueryService queryService =
                fidService.openFidQueryService(program.getLanguage(), false)) {

            FidProgramSeeker seeker = fidService.getProgramSeeker(
                program,
                queryService,
                fidService.getDefaultScoreThreshold()
            );

            List<FidSearchResult> searchResults = seeker.search(monitor);

            return toIdentifications(searchResults);
        }
    }

    private static List<FunctionIdentification> toIdentifications(
        List<FidSearchResult> searchResults
    ) {
        List<FunctionIdentification> identifications = new ArrayList<>();

        for (FidSearchResult searchResult : searchResults) {
            if (searchResult.matches.isEmpty()) {
                continue;
            }

            List<FidCandidate> candidates = new ArrayList<>(searchResult.matches.size());

            for (FidMatch match : searchResult.matches) {
                candidates.add(new FidCandidate(
                    match.getFunctionRecord().getName(),
                    match.getLibraryRecord().getLibraryFamilyName(),
                    match.getLibraryRecord().getLibraryVersion(),
                    match.getLibraryRecord().getLibraryVariant(),
                    match.getOverallScore(),
                    match.getPrimaryFunctionMatchMode().toString()
                ));
            }

            identifications.add(new FunctionIdentification(
                "0x" + Long.toUnsignedString(
                    searchResult.function.getEntryPoint().getOffset(),
                    16
                ),
                candidates
            ));
        }

        return identifications;
    }
}
