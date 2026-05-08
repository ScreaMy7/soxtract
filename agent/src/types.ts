export type ExtractionMethod =
  | "initial_enum"
  | "dlopen_hook"
  | "dlopen_ext_hook"
  | "memory_scan"
  | "disk_fallback";

export interface AgentConfig {
  chunkSize: number;       // bytes
  scanInterval: number;    // ms
  loaderDelay: number;     // ms
  retries: number;
  retryBackoffMs: number;
}

export interface ModuleInfo {
  name: string;
  base: NativePointer;
  size: number;
  path: string;
}

// ── Agent → Host messages ─────────────────────────────────────────────────

export interface LibFoundMsg {
  event: "lib_found";
  lib_id: string;
  transfer_id: string;
  name: string;
  base: string;   // hex "0x..."
  size: number;
  path: string;
  method: ExtractionMethod;
}

export interface ChunkMsg {
  event: "chunk";
  lib_id: string;
  transfer_id: string;
  seq: number;
  total: number;
  offset: number;
}

export interface LibDoneMsg {
  event: "lib_done";
  lib_id: string;
  transfer_id: string;
  total_bytes: number;
}

export interface LibErrorMsg {
  event: "lib_error";
  lib_id: string;
  transfer_id: string;
  error: string;
  retry_count: number;
}

export interface LibSkippedMsg {
  event: "lib_skipped";
  lib_id: string;
  reason: "duplicate" | "read_failed" | "not_elf";
}

export interface ScanStatusMsg {
  event: "scan_status";
  ranges_scanned: number;
  new_found: number;
  cached_skipped: number;
}

export type AgentMsg =
  | LibFoundMsg
  | ChunkMsg
  | LibDoneMsg
  | LibErrorMsg
  | LibSkippedMsg
  | ScanStatusMsg;
