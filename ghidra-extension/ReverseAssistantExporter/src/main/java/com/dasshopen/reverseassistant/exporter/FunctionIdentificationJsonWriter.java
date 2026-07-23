package com.dasshopen.reverseassistant.exporter;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

// Internal Rust<->Java exchange format for FunctionID identification results.
// Not part of the versioned ghidra-export-v1 contract and never persisted long-term.
public final class FunctionIdentificationJsonWriter {

    private final Gson gson;

    public FunctionIdentificationJsonWriter() {
        gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    }

    public String write(List<FunctionIdentification> identifications) {
        JsonArray root = new JsonArray();

        for (FunctionIdentification identification : identifications) {
            root.add(createIdentificationObject(identification));
        }

        return gson.toJson(root) + "\n";
    }

    private static JsonObject createIdentificationObject(
        FunctionIdentification identification
    ) {
        JsonObject object = new JsonObject();

        object.addProperty("entry_address", identification.entryAddress());
        object.add("candidates", createCandidatesArray(identification.candidates()));

        return object;
    }

    private static JsonArray createCandidatesArray(List<FidCandidate> candidates) {
        JsonArray array = new JsonArray();

        for (FidCandidate candidate : candidates) {
            JsonObject candidateObject = new JsonObject();

            candidateObject.addProperty("name", candidate.name());
            candidateObject.addProperty("library_family", candidate.libraryFamily());
            candidateObject.addProperty("library_version", candidate.libraryVersion());
            candidateObject.addProperty("library_variant", candidate.libraryVariant());
            candidateObject.addProperty("overall_score", candidate.overallScore());
            candidateObject.addProperty("match_mode", candidate.matchMode());

            array.add(candidateObject);
        }

        return array;
    }
}
