package com.dasshopen.reverseassistant.exporter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

// Internal Rust<->Java exchange format for on-demand decompilation requests.
// Not part of the versioned ghidra-export-v1 contract and never persisted long-term.
public final class DecompileResultJsonWriter {

    private final Gson gson;

    public DecompileResultJsonWriter() {
        gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    }

    public String write(
        DecompiledFunctionDetails details,
        BsimQueryResult bsimResult
    ) {
        JsonObject root = new JsonObject();

        if (details.decompiledCode() == null) {
            root.add("decompiled_code", JsonNull.INSTANCE);
        }
        else {
            root.addProperty("decompiled_code", details.decompiledCode());
        }

        root.addProperty("return_type", details.returnType());
        root.addProperty("calling_convention", details.callingConvention());

        JsonArray parameters = new JsonArray();

        for (FunctionParameterMetadata parameter : details.parameters()) {
            JsonObject parameterObject = new JsonObject();

            parameterObject.addProperty("name", parameter.name());
            parameterObject.addProperty("data_type", parameter.dataType());

            parameters.add(parameterObject);
        }

        root.add("parameters", parameters);

        JsonObject bsim = new JsonObject();
        bsim.addProperty("status", bsimResult.status());

        if (bsimResult.message() == null) {
            bsim.add("message", JsonNull.INSTANCE);
        }
        else {
            bsim.addProperty("message", bsimResult.message());
        }

        JsonArray bsimMatches = new JsonArray();

        for (BsimCandidate candidate : bsimResult.matches()) {
            JsonObject candidateObject = new JsonObject();
            candidateObject.addProperty("name", candidate.name());
            candidateObject.addProperty("executable", candidate.executable());
            candidateObject.addProperty("similarity", candidate.similarity());
            candidateObject.addProperty("significance", candidate.significance());
            bsimMatches.add(candidateObject);
        }

        bsim.add("matches", bsimMatches);
        root.add("bsim", bsim);

        return gson.toJson(root) + "\n";
    }
}
