// Ghidra headless script: decompile functions by name, print to stdout.
// Run: analyzeHeadless <proj> <name> -import <file> -postscript DecompileFuncs.java
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileFuncs extends GhidraScript {
    // Substring match on function names; edit as needed.
    static final String[] WANT = {
        "do_challenge",
        "do_normal_login",
    };

    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : funcs) {
            String name = f.getName();
            if (name.startsWith("_")) name = name.substring(1);
            boolean want = false;
            for (String w : WANT) {
                if (name.equals(w)) { want = true; break; }
            }
            if (!want) continue;
            println("\n===== " + name + " @ " + f.getEntryPoint() + " =====");
            DecompileResults res = ifc.decompileFunction(f, 120, monitor);
            if (res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("[decompile failed: " + res.getErrorMessage() + "]");
            }
        }
        ifc.dispose();
    }
}
