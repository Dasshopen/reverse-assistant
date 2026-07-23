// Identifies known library functions in the current program using Ghidra's
// FunctionID (FID) feature and writes the matches as JSON, headless-compatible.
// Reuses FunctionIdentificationService so headless and interactive runs stay identical.
//@category Reverse Assistant

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.dasshopen.reverseassistant.exporter.FunctionIdentificationService;

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class IdentifyFunctionsJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 1 || args[0].isBlank()) {
            printerr("Usage: IdentifyFunctionsJson <destination-json-path>");
            throw new IllegalArgumentException(
                "missing destination path for IdentifyFunctionsJson"
            );
        }

        if (currentProgram == null) {
            printerr("No program is loaded for identification.");
            throw new IllegalStateException("no current program to identify");
        }

        Path destination = Paths.get(args[0]);

        try {
            new FunctionIdentificationService().identifyAndWrite(
                currentProgram,
                destination,
                monitor
            );

            println("FunctionID identification results written to: " + destination);
        }
        catch (CancelledException exception) {
            printerr("FunctionID identification was cancelled.");
            throw exception;
        }
        catch (IOException exception) {
            printerr("FunctionID identification failed: " + exception.getMessage());
            throw exception;
        }
        catch (VersionException exception) {
            printerr("FunctionID identification failed (database version mismatch): " + exception.getMessage());
            throw exception;
        }
    }
}
