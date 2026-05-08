import { agentConfig } from "./config";
import { makeLibId, scheduleRead, seenLibs } from "./reader";

function toModuleInfo(m: Module) {
  return { name: m.name, base: m.base, size: m.size, path: m.path };
}

// ── Initial enumeration ───────────────────────────────────────────────────

export function enumerateLoadedModules(): void {
  Process.enumerateModules().forEach((m) => {
    if (!m.name.endsWith(".so")) return;
    scheduleRead(toModuleInfo(m), "initial_enum");
  });
}

// ── dlopen / android_dlopen_ext hooks ─────────────────────────────────────

function findExport(name: string): NativePointer | null {
  for (const mod of Process.enumerateModules()) {
    const addr = mod.findExportByName(name);
    if (addr !== null) return addr;
  }
  return null;
}

export function hookDlopenFunctions(): void {
  const targets: Array<["dlopen" | "android_dlopen_ext", "dlopen_hook" | "dlopen_ext_hook"]> = [
    ["dlopen", "dlopen_hook"],
    ["android_dlopen_ext", "dlopen_ext_hook"],
  ];

  for (const [sym, method] of targets) {
    const addr = findExport(sym);
    if (!addr) continue;

    Interceptor.attach(addr, {
      onLeave(retval) {
        if (retval.isNull()) return;
        const handle = retval;
        const delay = agentConfig.loaderDelay;

        setTimeout(() => {
          const mod = Process.findModuleByAddress(handle);
          if (!mod || !mod.name.endsWith(".so")) return;
          const libId = makeLibId(mod.name, mod.base);
          if (seenLibs.has(libId)) return;
          scheduleRead(toModuleInfo(mod), method);
        }, delay);
      },
    });
  }
}
