// Forces Ghidra's Universal PDB analyzer to use the exact symbol file paired
// with a reference binary. This avoids relying on a machine-specific absolute
// path embedded in the PE/COFF debug directory.

import java.io.File;

import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScript;

public class ConfigurePdb extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("ConfigurePdb expects exactly one PDB path");
        }

        File pdbFile = new File(arguments[0]).getCanonicalFile();
        if (!pdbFile.isFile()) {
            throw new IllegalArgumentException("PDB file not found: " + pdbFile);
        }

        PdbUniversalAnalyzer.setPdbFileOption(currentProgram, pdbFile);
        println("Configured PDB for analysis: " + pdbFile);
    }
}
