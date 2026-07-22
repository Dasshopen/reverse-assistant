// Exports the current program as a Reverse Assistant JSON v1 file, headless-compatible.
// Reuses ReverseAssistantExportService so headless and interactive exports stay identical.
//@category Reverse Assistant

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.dasshopen.reverseassistant.exporter.ReverseAssistantExportService;

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;

public class ExportReverseAssistantJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 1 || args[0].isBlank()) {
            printerr("Usage: ExportReverseAssistantJson <destination-json-path>");
            throw new IllegalArgumentException(
                "missing destination path for ExportReverseAssistantJson"
            );
        }

        if (currentProgram == null) {
            printerr("No program is loaded for export.");
            throw new IllegalStateException("no current program to export");
        }

        Path destination = Paths.get(args[0]);

        try {
            new ReverseAssistantExportService().export(
                currentProgram,
                destination,
                monitor
            );

            println("Reverse Assistant export written to: " + destination);
        }
        catch (CancelledException exception) {
            printerr("Reverse Assistant export was cancelled.");
            throw exception;
        }
        catch (IOException exception) {
            printerr("Reverse Assistant export failed: " + exception.getMessage());
            throw exception;
        }
    }
}
