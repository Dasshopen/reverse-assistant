// Disassembles a single function on demand and writes its instruction
// listing as JSON. Reuses FunctionDisassemblyService, headless-compatible.
//@category Reverse Assistant

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.dasshopen.reverseassistant.exporter.FunctionDisassemblyService;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

public class DisassembleFunctionJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 2 || args[0].isBlank() || args[1].isBlank()) {
            printerr("Usage: DisassembleFunctionJson <entry-address> <destination-json-path>");
            throw new IllegalArgumentException(
                "missing entry address or destination path for DisassembleFunctionJson"
            );
        }

        if (currentProgram == null) {
            printerr("No program is loaded for disassembly.");
            throw new IllegalStateException("no current program to disassemble");
        }

        Address entryAddress = toAddr(args[0]);

        if (entryAddress == null) {
            printerr("Not a valid address: " + args[0]);
            throw new IllegalArgumentException("invalid entry address: " + args[0]);
        }

        Path destination = Paths.get(args[1]);

        try {
            new FunctionDisassemblyService().disassembleAndWrite(
                currentProgram,
                entryAddress,
                destination,
                monitor
            );

            println("Disassembly result written to: " + destination);
        }
        catch (CancelledException exception) {
            printerr("Disassembly was cancelled.");
            throw exception;
        }
        catch (IOException exception) {
            printerr("Disassembly failed: " + exception.getMessage());
            throw exception;
        }
        catch (MemoryAccessException exception) {
            printerr("Disassembly failed: unable to read instruction bytes: " + exception.getMessage());
            throw exception;
        }
    }
}
