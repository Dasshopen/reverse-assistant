// Applies an atomic batch of user-confirmed function renames and exports the
// updated program metadata. Intended for a live Reverse Assistant project.
//@category Reverse Assistant

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

import com.dasshopen.reverseassistant.exporter.AtomicUtf8FileWriter;
import com.dasshopen.reverseassistant.exporter.ReverseAssistantExportService;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ApplyFunctionRenamesJson extends GhidraScript {

    private static final int MAX_RENAMES = 500;
    private static final int MAX_NAME_LENGTH = 512;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "Usage: ApplyFunctionRenamesJson <request-json> <result-json> <refreshed-export-json>"
            );
        }
        if (currentProgram == null) {
            throw new IllegalStateException("no current program is loaded");
        }

        Path requestPath = Paths.get(args[0]);
        Path resultPath = Paths.get(args[1]);
        Path refreshedExportPath = Paths.get(args[2]);
        JsonObject request = JsonParser.parseString(
            Files.readString(requestPath, StandardCharsets.UTF_8)
        ).getAsJsonObject();

        if (request.get("schema_version").getAsInt() != 1) {
            throw new IllegalArgumentException("unsupported rename request schema version");
        }
        JsonArray renames = request.getAsJsonArray("renames");
        if (renames == null || renames.isEmpty() || renames.size() > MAX_RENAMES) {
            throw new IllegalArgumentException("renames must contain between 1 and 500 entries");
        }

        Set<String> seenAddresses = new HashSet<>();
        JsonArray applied = new JsonArray();
        int transaction = currentProgram.startTransaction("Reverse Assistant function renames");
        boolean commit = false;

        try {
            for (JsonElement element : renames) {
                JsonObject rename = element.getAsJsonObject();
                String entryAddressText = rename.get("entry_address").getAsString();
                String newName = rename.get("new_name").getAsString().trim();

                if (!seenAddresses.add(entryAddressText)) {
                    throw new IllegalArgumentException("duplicate rename address: " + entryAddressText);
                }
                if (newName.isEmpty() || newName.length() > MAX_NAME_LENGTH) {
                    throw new IllegalArgumentException("invalid function name length at " + entryAddressText);
                }

                Address entryAddress = toAddr(entryAddressText);
                Function function = entryAddress == null
                    ? null
                    : currentProgram.getFunctionManager().getFunctionAt(entryAddress);
                if (function == null) {
                    throw new IllegalArgumentException("no function starts at " + entryAddressText);
                }
                if (function.isExternal()) {
                    throw new IllegalArgumentException("external functions cannot be renamed: " + entryAddressText);
                }

                String oldName = function.getName();
                function.setName(newName, SourceType.USER_DEFINED);

                JsonObject appliedRename = new JsonObject();
                appliedRename.addProperty("entry_address", entryAddressText);
                appliedRename.addProperty("old_name", oldName);
                appliedRename.addProperty("new_name", function.getName());
                applied.add(appliedRename);
            }

            // Export while the transaction is still open. If export or result
            // writing fails, the transaction is rolled back and Rust refuses
            // to accept either incomplete output.
            new ReverseAssistantExportService().export(
                currentProgram,
                refreshedExportPath,
                monitor
            );

            JsonObject result = new JsonObject();
            result.addProperty("schema_version", 1);
            result.add("applied", applied);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            new AtomicUtf8FileWriter().write(resultPath, gson.toJson(result));
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }

        println("Applied " + applied.size() + " function rename(s).");
    }
}
