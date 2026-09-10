import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

export const config = {
  backendUrl: process.env.BACKEND_URL || "http://localhost:5050",
  agentToken: process.env.AGENT_TOKEN || "",
  userId: process.env.USER_ID || "",

  // Collector poll intervals (ms)
  processPollIntervalMs: Number(process.env.PROCESS_POLL_INTERVAL_MS) || 5_000,
  networkPollIntervalMs: Number(process.env.NETWORK_POLL_INTERVAL_MS) || 8_000,

  // Batch & Heartbeat intervals
  batchIntervalMs: Number(process.env.BATCH_INTERVAL_MS) || 3_000,
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS) || 10_000,

  // Bounded local buffer
  maxBufferedFindings: Number(process.env.MAX_BUFFERED_FINDINGS) || 500,

  // Detection windows
  bruteForceWindowMinutes: Number(process.env.BRUTE_FORCE_WINDOW_MINUTES) || 10,
  correlationWindowMinutes: Number(process.env.CORRELATION_WINDOW_MINUTES) || 10,
};

export function assertConfigured() {
  if (!config.agentToken) {
    throw new Error(
      "AGENT_TOKEN is not set. Pair this device from the Rakshak dashboard " +
      "(Settings > Local SOC Agent Pairing) and copy the token into agent/.env"
    );
  }
}
