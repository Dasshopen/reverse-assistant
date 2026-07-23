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

    public String write(DecompiledFunctionDetails details) {
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

        return gson.toJson(root) + "\n";
    }
}
