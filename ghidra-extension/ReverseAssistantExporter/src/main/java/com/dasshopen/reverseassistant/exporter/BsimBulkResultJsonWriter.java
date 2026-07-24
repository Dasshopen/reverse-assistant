package com.dasshopen.reverseassistant.exporter;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

public final class BsimBulkResultJsonWriter {

    private final Gson gson = new GsonBuilder()
        .setPrettyPrinting()
        .disableHtmlEscaping()
        .serializeNulls()
        .create();

    public String write(List<BsimBulkFunctionResult> results) {
        JsonArray root = new JsonArray();
        for (BsimBulkFunctionResult result : results) {
            JsonObject item = new JsonObject();
            item.addProperty("entry_address", result.entryAddress());
            item.add("candidates", new JsonArray());
            item.addProperty("bsim_scanned", result.scanned());
            if (result.message() == null) {
                item.add("bsim_message", JsonNull.INSTANCE);
            }
            else {
                item.addProperty("bsim_message", result.message());
            }
            JsonArray matches = new JsonArray();
            for (BsimCandidate candidate : result.candidates()) {
                JsonObject match = new JsonObject();
                match.addProperty("name", candidate.name());
                match.addProperty("executable", candidate.executable());
                match.addProperty("corpus", candidate.corpus());
                match.addProperty("similarity", candidate.similarity());
                match.addProperty("significance", candidate.significance());
                matches.add(match);
            }
            item.add("bsim_candidates", matches);
            root.add(item);
        }
        return gson.toJson(root) + "\n";
    }
}
