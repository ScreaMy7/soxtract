import { agentConfig } from "./config";
import type { ExtractionMethod, ModuleInfo } from "./types";

// ── Shared dedup state ────────────────────────────────────────────────────

export const seenLibs = new Set<string>();

export function makeLibId(name: string, base: NativePointer): string {
  return `${name}@${base}`;
}

// ── UUID helper ───────────────────────────────────────────────────────────

function uuid(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ── Read job ──────────────────────────────────────────────────────────────

interface ReadJob {
  mod: ModuleInfo;
  method: ExtractionMethod;
  retriesLeft: number;
  backoffMs: number;
}

/**
 * Schedule a new read for a module.  The seenLibs guard prevents duplicate
 * scheduling; the guard is NOT removed on failure — retries bypass it by
 * calling readModuleMemory directly.
 */
export function scheduleRead(
  mod: ModuleInfo,
  method: ExtractionMethod,
): void {
  const libId = makeLibId(mod.name, mod.base);
  if (seenLibs.has(libId)) return;
  seenLibs.add(libId);

  setTimeout(() =>
    readModuleMemory({
      mod,
      method,
      retriesLeft: agentConfig.retries,
      backoffMs: agentConfig.retryBackoffMs,
    }), 0);
}

// ── Core memory reader ────────────────────────────────────────────────────

function readModuleMemory(job: ReadJob): void {
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
    method,
  });

  let offset = 0;
  let seq = 0;
  let errorMsg: string | null = null;

  while (offset < totalSize) {
    const thisChunk = Math.min(chunkSize, totalSize - offset);
    try {
      const bytes = mod.base.add(offset).readByteArray(thisChunk);
      if (bytes === null) {
        errorMsg = "readByteArray returned null";
        break;
      }
      send(
        {
          event: "chunk",
          lib_id: libId,
          transfer_id: transferId,
          seq,
          total: totalChunks,
          offset,
        },
        bytes,
      );
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
      retry_count: retryCount,
    });

    if (job.retriesLeft > 0) {
      setTimeout(
        () =>
          readModuleMemory({
            mod,
            method,
            retriesLeft: job.retriesLeft - 1,
            backoffMs: job.backoffMs * 2,
          }),
        job.backoffMs,
      );
    } else {
      tryDiskFallback(mod, libId);
    }
    return;
  }

  send({
    event: "lib_done",
    lib_id: libId,
    transfer_id: transferId,
    total_bytes: totalSize,
  });
}

// ── Disk fallback ─────────────────────────────────────────────────────────

function tryDiskFallback(mod: ModuleInfo, libId: string): void {
  if (!mod.path) {
    send({ event: "lib_skipped", lib_id: libId, reason: "read_failed" });
    return;
  }
  try {
    const transferId = uuid();
    const file = new File(mod.path, "rb");
    const bytes = file.readBytes(mod.size) as ArrayBuffer;
    file.close();

    const totalBytes = (bytes as ArrayBuffer).byteLength;

    send({
      event: "lib_found",
      lib_id: libId,
      transfer_id: transferId,
      name: mod.name,
      base: mod.base.toString(),
      size: totalBytes,
      path: mod.path,
      method: "disk_fallback",
    });
    send(
      {
        event: "chunk",
        lib_id: libId,
        transfer_id: transferId,
        seq: 0,
        total: 1,
        offset: 0,
      },
      bytes,
    );
    send({
      event: "lib_done",
      lib_id: libId,
      transfer_id: transferId,
      total_bytes: totalBytes,
    });
  } catch (_e) {
    send({ event: "lib_skipped", lib_id: libId, reason: "read_failed" });
  }
}
