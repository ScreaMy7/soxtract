import { agentConfig } from "./config";
import { makeLibId, scheduleRead, seenLibs } from "./reader";

// Cache of range keys we have already inspected.  Key format: "${base}-${size}".
const scannedRangeCache = new Set<string>();

let scanTimer: ReturnType<typeof setInterval> | null = null;

function rangeKey(base: NativePointer, size: number): string {
  return `${base}-${size}`;
}

function isElfMagic(buf: ArrayBuffer | null): boolean {
  if (!buf || buf.byteLength < 4) return false;
  const view = new Uint8Array(buf);
  return view[0] === 0x7f && view[1] === 0x45 && view[2] === 0x4c && view[3] === 0x46;
}

function scanForNewElfs(): void {
  const live = Process.enumerateRanges("r-x");
  let scanned = 0;
  let newFound = 0;
  let cached = 0;

  // Evict stale entries (ranges that are no longer mapped)
  const liveKeys = new Set(live.map((r) => rangeKey(r.base, r.size)));
  for (const k of scannedRangeCache) {
    if (!liveKeys.has(k)) scannedRangeCache.delete(k);
  }

  for (const range of live) {
    const key = rangeKey(range.base, range.size);
    if (scannedRangeCache.has(key)) {
      cached++;
      continue;
    }
    scannedRangeCache.add(key);
    scanned++;

    try {
      const magic = range.base.readByteArray(4);
      if (!isElfMagic(magic)) continue;

      const mod = Process.findModuleByAddress(range.base);
      const name = mod?.name ?? `anon_${range.base.toString().replace("0x", "")}.so`;
      const path = mod?.path ?? "";
      const size = mod?.size ?? range.size;

      if (!name.endsWith(".so")) continue;

      const libId = makeLibId(name, range.base);
      if (seenLibs.has(libId)) continue;

      newFound++;
      scheduleRead({ name, base: range.base, size, path }, "memory_scan");
    } catch (_e) {
      // Unreadable range — already cached, won't retry
    }
  }

  send({
    event: "scan_status",
    ranges_scanned: scanned,
    new_found: newFound,
    cached_skipped: cached,
  });
}

export function startScanner(): void {
  scanTimer = setInterval(scanForNewElfs, agentConfig.scanInterval);
}

export function stopScanner(): void {
  if (scanTimer !== null) {
    clearInterval(scanTimer);
    scanTimer = null;
  }
}
