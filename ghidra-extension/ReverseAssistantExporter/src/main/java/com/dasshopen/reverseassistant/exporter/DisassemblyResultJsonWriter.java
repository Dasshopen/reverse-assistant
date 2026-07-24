package com.dasshopen.reverseassistant.exporter;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

// Internal Rust<->Java exchange format for on-demand disassembly requests.
// Not part of the versioned ghidra-export-v1/v2 contract and never
// persisted long-term (same convention as DecompileResultJsonWriter).
public final class DisassemblyResultJsonWriter {

    private final Gson gson;

    public DisassemblyResultJsonWriter() {
        gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    }

    public String write(List<DisassembledInstructionMetadata> instructions) {
        JsonObject root = new JsonObject();
        JsonArray instructionsArray = new JsonArray();

        for (DisassembledInstructionMetadata instruction : instructions) {
            JsonObject instructionObject = new JsonObject();

            instructionObject.addProperty("address", instruction.address());
            instructionObject.addProperty("length", instruction.length());
            instructionObject.addProperty("bytes", instruction.bytes());
            instructionObject.addProperty("mnemonic", instruction.mnemonic());
            instructionObject.addProperty("operands", instruction.operands());
            instructionObject.addProperty("flow_category", instruction.flowCategory());

            if (instruction.fallThroughAddress() == null) {
                instructionObject.add("fall_through_address", JsonNull.INSTANCE);
            }
            else {
                instructionObject.addProperty(
                    "fall_through_address",
                    instruction.fallThroughAddress()
                );
            }

            instructionsArray.add(instructionObject);
        }

        root.add("instructions", instructionsArray);

        return gson.toJson(root) + "\n";
    }
}
