// Disables Ghidra analyzers that call the decompiler internally during bulk
// analysis (Decompiler Parameter ID, Decompiler Switch Analysis). On complex
// optimized binaries these can dominate analysis time (observed: 33+ minutes,
// never completing, on a 9MB release binary; ~3 minutes with both disabled).
// Neither commits its refined signature to the program, so on-demand
// decompilation (DecompileFunctionJson.java) still recovers a full prototype
// for a specific function when requested, independently of this setting.
//@category Reverse Assistant

public class DisableSlowAnalyzers extends ghidra.app.script.GhidraScript {

    @Override
    protected void run() throws Exception {
        setAnalysisOption(currentProgram, "Decompiler Parameter ID", "false");
        setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "false");
    }
}
