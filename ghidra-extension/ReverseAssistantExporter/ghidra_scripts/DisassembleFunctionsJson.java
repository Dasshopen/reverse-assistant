// Disassembles a bounded list of functions on demand and writes their
// combined instruction listing as JSON. Reuses FunctionDisassemblyService,
// headless-compatible. Used for a "whole program" Code Browser page: the
// caller (Rust) picks a bounded slice of function addresses from the
// already-loaded export rather than this script ever walking the entire
// program itself.
//@category Reverse Assistant

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.dasshopen.reverseassistant.exporter.FunctionDisassemblyService;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

public class DisassembleFunctionsJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 2 || args[0].isBlank()) {
            printerr("Usage: DisassembleFunctionsJson <destination-json-path> <entry-address>...");
            throw new IllegalArgumentException(
                "missing destination path or entry addresses for DisassembleFunctionsJson"
            );
        }

        if (currentProgram == null) {
            printerr("No program is loaded for disassembly.");
            throw new IllegalStateException("no current program to disassemble");
        }

        Path destination = Paths.get(args[0]);
        List<Address> entryAddresses = new ArrayList<>();

        for (int index = 1; index < args.length; index++) {
            Address entryAddress = toAddr(args[index]);

            if (entryAddress == null) {
                printerr("Not a valid address: " + args[index]);
                throw new IllegalArgumentException("invalid entry address: " + args[index]);
            }

            entryAddresses.add(entryAddress);
        }

        try {
            new FunctionDisassemblyService().disassembleManyAndWrite(
                currentProgram,
                entryAddresses,
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
