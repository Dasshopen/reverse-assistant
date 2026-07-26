// Decompiles a bounded list of functions in one Ghidra/JVM launch. This is
// used by the AI naming pipeline so it does not pay analyzeHeadless startup
// once per function.
//@category Reverse Assistant

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.dasshopen.reverseassistant.exporter.AtomicUtf8FileWriter;
import com.dasshopen.reverseassistant.exporter.DecompiledFunctionDetails;
import com.dasshopen.reverseassistant.exporter.FunctionDecompiler;
import com.dasshopen.reverseassistant.exporter.FunctionParameterMetadata;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFunctionsJson extends GhidraScript {

    private static final int MAX_FUNCTIONS = 500;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException(
                "Usage: DecompileFunctionsJson <addresses-json> <destination-json>"
            );
        }
        if (currentProgram == null) {
            throw new IllegalStateException("no current program for batch decompilation");
        }

        Path requestPath = Paths.get(args[0]);
        Path destination = Paths.get(args[1]);
        JsonArray addresses = JsonParser.parseString(
            Files.readString(requestPath, StandardCharsets.UTF_8)
        ).getAsJsonArray();
        if (addresses.isEmpty() || addresses.size() > MAX_FUNCTIONS) {
            throw new IllegalArgumentException(
                "the batch must contain between 1 and " + MAX_FUNCTIONS + " addresses"
            );
        }

        JsonArray output = new JsonArray();
        DecompInterface decompiler = FunctionDecompiler.createDecompiler(currentProgram);
        try {
            monitor.initialize(addresses.size(), "Preparing AI function context");
            for (int index = 0; index < addresses.size(); index++) {
                monitor.checkCancelled();
                String addressText = addresses.get(index).getAsString();
                JsonObject item = new JsonObject();
                item.addProperty("entry_address", addressText);
                try {
                    Address address = currentProgram.getAddressFactory().getAddress(addressText);
                    Function function = address == null
                        ? null
                        : currentProgram.getFunctionManager().getFunctionAt(address);
                    if (function == null) {
                        throw new IllegalArgumentException("no function exists at " + addressText);
                    }
                    DecompiledFunctionDetails details = FunctionDecompiler.decompile(
                        function, decompiler, monitor
                    );
                    if (details.decompiledCode() == null) {
                        item.add("decompiled_code", JsonNull.INSTANCE);
                    }
                    else {
                        item.addProperty("decompiled_code", details.decompiledCode());
                    }
                    item.addProperty("return_type", details.returnType());
                    item.addProperty("calling_convention", details.callingConvention());
                    JsonArray parameters = new JsonArray();
                    for (FunctionParameterMetadata parameter : details.parameters()) {
                        JsonObject value = new JsonObject();
                        value.addProperty("name", parameter.name());
                        value.addProperty("data_type", parameter.dataType());
                        parameters.add(value);
                    }
                    item.add("parameters", parameters);
                    item.add("error", JsonNull.INSTANCE);
                }
                catch (Exception exception) {
                    item.add("decompiled_code", JsonNull.INSTANCE);
                    item.addProperty("return_type", "unknown");
                    item.addProperty("calling_convention", "unknown");
                    item.add("parameters", new JsonArray());
                    item.addProperty("error", exception.getMessage());
                }
                output.add(item);
                monitor.incrementProgress(1);
            }
        }
        finally {
            decompiler.dispose();
        }

        new AtomicUtf8FileWriter().write(
            destination,
            new Gson().toJson(output) + "\n"
        );
        println("Prepared AI context for " + output.size() + " function(s): " + destination);
    }
}
