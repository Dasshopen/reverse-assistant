// Queries every still-unnamed internal function against all configured BSim
// corpora in bounded batches and writes durable evidence for the app.
//@category Reverse Assistant

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.dasshopen.reverseassistant.exporter.AtomicUtf8FileWriter;
import com.dasshopen.reverseassistant.exporter.BsimBulkFunctionResult;
import com.dasshopen.reverseassistant.exporter.BsimBulkQueryService;
import com.dasshopen.reverseassistant.exporter.BsimBulkResultJsonWriter;
import com.dasshopen.reverseassistant.exporter.BsimCorpus;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class QueryBsimFunctionsJson extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args[0].isBlank()) {
            throw new IllegalArgumentException(
                "Usage: QueryBsimFunctionsJson <destination-json> [--bsim-corpus <id> <name> <database-url>]..."
            );
        }
        if ((args.length - 1) % 4 != 0) {
            throw new IllegalArgumentException("invalid BSim corpus arguments");
        }
        if (currentProgram == null) {
            throw new IllegalStateException("no current program for BSim scanning");
        }

        Path destination = Paths.get(args[0]);
        List<BsimCorpus> corpora = new ArrayList<>();
        for (int index = 1; index < args.length; index += 4) {
            if (!"--bsim-corpus".equals(args[index])) {
                throw new IllegalArgumentException("invalid BSim corpus arguments");
            }
            corpora.add(new BsimCorpus(args[index + 1], args[index + 2], args[index + 3]));
        }

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            String name = function.getName();
            if (!function.isExternal() &&
                (name.matches("(?i)^(?:thunk_)?FUN_[0-9a-f]+$") ||
                 name.matches("(?i)^sub_[0-9a-f]+$"))) {
                functions.add(function);
            }
        }

        List<BsimBulkFunctionResult> results = corpora.isEmpty()
            ? List.of()
            : new BsimBulkQueryService().query(currentProgram, functions, corpora, monitor);
        new AtomicUtf8FileWriter().write(
            destination,
            new BsimBulkResultJsonWriter().write(results)
        );
        println("BSim bulk results written for " + results.size() + " function(s): " + destination);
    }
}
