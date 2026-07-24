// Decompiles a single function on demand and writes its pseudocode as JSON.
// Reuses DecompileFunctionService, headless-compatible.
//@category Reverse Assistant

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.dasshopen.reverseassistant.exporter.BsimCorpus;
import com.dasshopen.reverseassistant.exporter.DecompileFunctionService;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;

public class DecompileFunctionJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 2 || args[0].isBlank() || args[1].isBlank()) {
            printerr("Usage: DecompileFunctionJson <entry-address> <destination-json-path> [--bsim-corpus <id> <name> <database-url>]...");
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
        List<BsimCorpus> bsimCorpora = new ArrayList<>();
        for (int index = 2; index < args.length; index += 4) {
            if (index + 3 >= args.length || !"--bsim-corpus".equals(args[index])) {
                throw new IllegalArgumentException("invalid BSim corpus arguments");
            }
            bsimCorpora.add(new BsimCorpus(args[index + 1], args[index + 2], args[index + 3]));
        }

        try {
            new DecompileFunctionService().decompileAndWrite(
                currentProgram,
                entryAddress,
                destination,
                bsimCorpora,
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
