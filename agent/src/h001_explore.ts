import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        // Enumerate classes related to Hybrid
        const classes = Java.enumerateLoadedClassesSync();
        const hybrid = classes.filter((c: string) => 
            c.toLowerCase().includes('hybrid') || 
            c.toLowerCase().includes('nmphandler') ||
            c.toLowerCase().includes('webview') && c.includes('schibsted')
        );
        hybrid.forEach((c: string) => console.log('[CLASS] ' + c));
        console.log('[TOTAL-HYBRID] ' + hybrid.length + ' hybrid-related classes found');
        
        // Also try to find any NMP-related classes
        const nmp = classes.filter((c: string) => c.includes('com.schibsted.nmp') && 
            (c.includes('Handler') || c.includes('View') || c.includes('Fragment')));
        nmp.slice(0, 30).forEach((c: string) => console.log('[NMP-CLASS] ' + c));
    });
}

run();
