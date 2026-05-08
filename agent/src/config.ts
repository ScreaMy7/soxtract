import type { AgentConfig } from "./types";

export const agentConfig: AgentConfig = {
  chunkSize: 256 * 1024,   // 256 KB
  scanInterval: 5000,
  loaderDelay: 250,
  retries: 3,
  retryBackoffMs: 500,
};

export function configure(cfg: Partial<AgentConfig>): void {
  Object.assign(agentConfig, cfg);
}
