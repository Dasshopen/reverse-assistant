// Removes corpus-only functions that cannot provide a useful user-facing name.
// Run as a postScript after analysis and before `bsim generatesigs`.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;

public class RemoveUnusableBsimFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        int removed = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();

            if (function.isExternal() || function.isThunk()) {
                continue;
            }

            String name = function.getName();
            boolean defaultSymbol = function.getSymbol().getSource() == SourceType.DEFAULT;
            boolean genericName = name.matches("(?i)^(?:thunk_)?FUN_[0-9a-f]+$")
                || name.matches("(?i)^sub_[0-9a-f]+$")
                || name.matches("(?i)^LAB_[0-9a-f]+$");
            boolean stringLiteralSymbol = name.startsWith("??_C@");

            if (defaultSymbol || genericName || stringLiteralSymbol) {
                currentProgram.getFunctionManager().removeFunction(function.getEntryPoint());
                removed++;
            }
        }

        println("Removed " + removed + " unusable BSim reference functions");
    }
}
