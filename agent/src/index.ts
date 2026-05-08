import { configure } from "./config";
import type { AgentConfig } from "./types";
import { enumerateLoadedModules, hookDlopenFunctions } from "./modules";
import { startScanner, stopScanner } from "./scanner";

rpc.exports = {
  configure(cfg: AgentConfig): void {
    configure(cfg);
  },
  stop(): void {
    stopScanner();
  },
};

// Run immediately on injection
enumerateLoadedModules();
hookDlopenFunctions();
startScanner();
