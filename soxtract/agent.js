📦
6710 /src/index.js
✄
// src/config.ts
var agentConfig = {
  chunkSize: 256 * 1024,
  // 256 KB
  scanInterval: 5e3,
  loaderDelay: 250,
  retries: 3,
  retryBackoffMs: 500
};
function configure(cfg) {
  Object.assign(agentConfig, cfg);
}

// src/reader.ts
var seenLibs = /* @__PURE__ */ new Set();
function makeLibId(name, base) {
  return `${name}@${base}`;
}
function uuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
function scheduleRead(mod, method) {
  const libId = makeLibId(mod.name, mod.base);
  if (seenLibs.has(libId))
    return;
  seenLibs.add(libId);
  setTimeout(() => readModuleMemory({
    mod,
    method,
    retriesLeft: agentConfig.retries,
    backoffMs: agentConfig.retryBackoffMs
  }), 0);
}
function readModuleMemory(job) {
  const { mod, method } = job;
  const libId = makeLibId(mod.name, mod.base);
  const transferId = uuid();
  const chunkSize = agentConfig.chunkSize;
  const totalSize = mod.size;
  const totalChunks = Math.ceil(totalSize / chunkSize);
  send({
    event: "lib_found",
    lib_id: libId,
    transfer_id: transferId,
    name: mod.name,
    base: mod.base.toString(),
    size: totalSize,
    path: mod.path,
    method
  });
  let offset = 0;
  let seq = 0;
  let errorMsg = null;
  while (offset < totalSize) {
    const thisChunk = Math.min(chunkSize, totalSize - offset);
    try {
      const bytes = mod.base.add(offset).readByteArray(thisChunk);
      if (bytes === null) {
        errorMsg = "readByteArray returned null";
        break;
      }
      send({
        event: "chunk",
        lib_id: libId,
        transfer_id: transferId,
        seq,
        total: totalChunks,
        offset
      }, bytes);
      offset += thisChunk;
      seq++;
    } catch (e) {
      errorMsg = String(e);
      break;
    }
  }
  if (errorMsg !== null) {
    const retryCount = agentConfig.retries - job.retriesLeft;
    send({
      event: "lib_error",
      lib_id: libId,
      transfer_id: transferId,
      error: errorMsg,
      retry_count: retryCount
    });
    if (job.retriesLeft > 0) {
      setTimeout(() => readModuleMemory({
        mod,
        method,
        retriesLeft: job.retriesLeft - 1,
        backoffMs: job.backoffMs * 2
      }), job.backoffMs);
    } else {
      tryDiskFallback(mod, libId);
    }
    return;
  }
  send({
    event: "lib_done",
    lib_id: libId,
    transfer_id: transferId,
    total_bytes: totalSize
  });
}
function tryDiskFallback(mod, libId) {
  if (!mod.path) {
    send({ event: "lib_skipped", lib_id: libId, reason: "read_failed" });
    return;
  }
  try {
    const transferId = uuid();
    const file = new File(mod.path, "rb");
    const bytes = file.readBytes(mod.size);
    file.close();
    const totalBytes = bytes.byteLength;
    send({
      event: "lib_found",
      lib_id: libId,
      transfer_id: transferId,
      name: mod.name,
      base: mod.base.toString(),
      size: totalBytes,
      path: mod.path,
      method: "disk_fallback"
    });
    send({
      event: "chunk",
      lib_id: libId,
      transfer_id: transferId,
      seq: 0,
      total: 1,
      offset: 0
    }, bytes);
    send({
      event: "lib_done",
      lib_id: libId,
      transfer_id: transferId,
      total_bytes: totalBytes
    });
  } catch (_e) {
    send({ event: "lib_skipped", lib_id: libId, reason: "read_failed" });
  }
}

// src/modules.ts
function toModuleInfo(m) {
  return { name: m.name, base: m.base, size: m.size, path: m.path };
}
function enumerateLoadedModules() {
  Process.enumerateModules().forEach((m) => {
    if (!m.name.endsWith(".so"))
      return;
    scheduleRead(toModuleInfo(m), "initial_enum");
  });
}
function findExport(name) {
  for (const mod of Process.enumerateModules()) {
    const addr = mod.findExportByName(name);
    if (addr !== null)
      return addr;
  }
  return null;
}
function hookDlopenFunctions() {
  const targets = [
    ["dlopen", "dlopen_hook"],
    ["android_dlopen_ext", "dlopen_ext_hook"]
  ];
  for (const [sym, method] of targets) {
    const addr = findExport(sym);
    if (!addr)
      continue;
    Interceptor.attach(addr, {
      onLeave(retval) {
        if (retval.isNull())
          return;
        const handle = retval;
        const delay = agentConfig.loaderDelay;
        setTimeout(() => {
          const mod = Process.findModuleByAddress(handle);
          if (!mod || !mod.name.endsWith(".so"))
            return;
          const libId = makeLibId(mod.name, mod.base);
          if (seenLibs.has(libId))
            return;
          scheduleRead(toModuleInfo(mod), method);
        }, delay);
      }
    });
  }
}

// src/scanner.ts
var scannedRangeCache = /* @__PURE__ */ new Set();
var scanTimer = null;
function rangeKey(base, size) {
  return `${base}-${size}`;
}
function isElfMagic(buf) {
  if (!buf || buf.byteLength < 4)
    return false;
  const view = new Uint8Array(buf);
  return view[0] === 127 && view[1] === 69 && view[2] === 76 && view[3] === 70;
}
function scanForNewElfs() {
  const live = Process.enumerateRanges("r-x");
  let scanned = 0;
  let newFound = 0;
  let cached = 0;
  const liveKeys = new Set(live.map((r) => rangeKey(r.base, r.size)));
  for (const k of scannedRangeCache) {
    if (!liveKeys.has(k))
      scannedRangeCache.delete(k);
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
      if (!isElfMagic(magic))
        continue;
      const mod = Process.findModuleByAddress(range.base);
      const name = mod?.name ?? `anon_${range.base.toString().replace("0x", "")}.so`;
      const path = mod?.path ?? "";
      const size = mod?.size ?? range.size;
      if (!name.endsWith(".so"))
        continue;
      const libId = makeLibId(name, range.base);
      if (seenLibs.has(libId))
        continue;
      newFound++;
      scheduleRead({ name, base: range.base, size, path }, "memory_scan");
    } catch (_e) {
    }
  }
  send({
    event: "scan_status",
    ranges_scanned: scanned,
    new_found: newFound,
    cached_skipped: cached
  });
}
function startScanner() {
  scanTimer = setInterval(scanForNewElfs, agentConfig.scanInterval);
}
function stopScanner() {
  if (scanTimer !== null) {
    clearInterval(scanTimer);
    scanTimer = null;
  }
}

// src/index.ts
rpc.exports = {
  configure(cfg) {
    configure(cfg);
  },
  stop() {
    stopScanner();
  }
};
enumerateLoadedModules();
hookDlopenFunctions();
startScanner();
