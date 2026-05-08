import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const NMPHybridHandler = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
        
        // List all overloads of $init
        const initMethod = NMPHybridHandler.$init;
        if (initMethod && initMethod.overloads) {
            for (const overload of initMethod.overloads) {
                console.log("[H001-CTOR] Overload: " + overload.argumentTypes.map((t: any) => t.className).join(", "));
            }
        } else {
            console.log("[H001-CTOR] No overloads or $init not accessible");
        }
        
        // Also list handleLogin overloads
        const loginMethod = NMPHybridHandler.handleLogin;
        if (loginMethod && loginMethod.overloads) {
            for (const overload of loginMethod.overloads) {
                console.log("[H001-LOGIN] Overload: " + overload.argumentTypes.map((t: any) => t.className).join(", "));
            }
        }
        
        // List all declared methods
        const javaClass = NMPHybridHandler.class;
        const methods = javaClass.getDeclaredMethods();
        for (let i = 0; i < methods.length; i++) {
            console.log("[H001-METHOD] " + methods[i].toString());
        }
    });
}

run();
