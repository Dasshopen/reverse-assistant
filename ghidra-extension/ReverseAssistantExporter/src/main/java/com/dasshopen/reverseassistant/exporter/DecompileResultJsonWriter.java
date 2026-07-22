package com.dasshopen.reverseassistant.exporter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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

    public String write(String decompiledCode) {
        JsonObject root = new JsonObject();

        if (decompiledCode == null) {
            root.add("decompiled_code", JsonNull.INSTANCE);
        }
        else {
            root.addProperty("decompiled_code", decompiledCode);
        }

        return gson.toJson(root) + "\n";
    }
}
