// Decompiles a single function on demand and writes its pseudocode as JSON.
// Reuses DecompileFunctionService, headless-compatible.
//@category Reverse Assistant

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.dasshopen.reverseassistant.exporter.DecompileFunctionService;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;

public class DecompileFunctionJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 2 || args[0].isBlank() || args[1].isBlank()) {
            printerr("Usage: DecompileFunctionJson <entry-address> <destination-json-path>");
            throw new IllegalArgumentException(
                "missing entry address or destination path for DecompileFunctionJson"
            );
        }

        if (currentProgram == null) {
            printerr("No program is loaded for decompilation.");
            throw new IllegalStateException("no current program to decompile");
        }

        Address entryAddress = toAddr(args[0]);

        if (entryAddress == null) {
            printerr("Not a valid address: " + args[0]);
            throw new IllegalArgumentException("invalid entry address: " + args[0]);
        }

        Path destination = Paths.get(args[1]);

        try {
            new DecompileFunctionService().decompileAndWrite(
                currentProgram,
                entryAddress,
                destination,
                monitor
            );

            println("Decompile result written to: " + destination);
        }
        catch (CancelledException exception) {
            printerr("Decompilation was cancelled.");
            throw exception;
        }
        catch (IOException exception) {
            printerr("Decompilation failed: " + exception.getMessage());
            throw exception;
        }
    }
}
