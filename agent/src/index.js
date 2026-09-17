import { config, assertConfigured } from "./config.js";
import { ensureDevicePermissionGranted, watchConsent } from "./consent.js";
import { startSystemLogCollector } from "./collectors/systemLogCollector.js";
import { startProcessCollector } from "./collectors/processCollector.js";
import { startNetworkCollector } from "./collectors/networkCollector.js";
import { startHoneytokenCollector } from "./collectors/honeytokenCollector.js";
import { ThreatClassifier } from "./detection/classify.js";
import { CorrelationEngine } from "./correlation/correlate.js";
import { AgentTransport } from "./transport/client.js";

function log(message) {
  console.log(`[${new Date().toISOString()}] ${message}`);
}

async function main() {
  assertConfigured();

  // Ask / verify device monitoring permission before accessing any host resources
  const permissionGranted = await ensureDevicePermissionGranted();

  const classifier = new ThreatClassifier();
  const correlator = new CorrelationEngine();
  const transport = new AgentTransport({ onLog: log }).connect();

  // Every normalized event from any collector flows through:
  // 1. Classification & correlation (for security alerts)
  // 2. Activity streaming (for continuous host visibility)
  function handleEvent(event) {
    const candidates = classifier.classifyEvent(event);
    const hasThreat = candidates.length > 0;
    const topCandidate = candidates[0] || null;

    for (const candidate of candidates) {
      log(`Finding: ${candidate.type} (${candidate.severity}) ${candidate.sourceIp || ""}`);
      transport.enqueue(candidate);

      const incident = correlator.ingest(candidate);
      if (incident) {
        log(`Correlated incident: ${incident.title}`);
        transport.enqueue(incident);
      }
    }

    // Continuous Activity Stream for every host event
    let action = `${event.source}.event`;
    let actor = 'system';
    let entity = '';
    let metadata = {};

    try {
      if (event.raw && typeof event.raw === 'string' && event.raw.startsWith('{')) {
        metadata = JSON.parse(event.raw);
      }
    } catch {}

    if (event.source === 'process') {
      action = metadata.changeType ? `process.${metadata.changeType}` : 'process.active';
      actor = metadata.user || 'system';
      entity = metadata.processName || metadata.command || '';
    } else if (event.source === 'network') {
      action = metadata.changeType ? `connection.${metadata.changeType}` : 'connection.active';
      actor = metadata.user || metadata.command || 'system';
      entity = metadata.remoteIp ? `${metadata.remoteIp}:${metadata.remotePort}` : '';
    } else if (event.source === 'log') {
      action = 'system.log';
      actor = 'system';
      entity = event.ip || '';
    }

    const activity = {
      source: event.source || 'process',
      action,
      description: event.message || 'Host activity recorded',
      actor,
      entity,
      ip: event.ip || metadata.remoteIp || null,
      isThreat: hasThreat,
      severity: topCandidate ? topCandidate.severity : 'none',
      threatType: topCandidate ? topCandidate.type : null,
      metadata,
      timestamp: event.timestamp || new Date().toISOString(),
    };

    transport.enqueueActivity(activity);
  }

  function handleError(err) {
    log(`Collector error: ${err.message}`);
  }

  log(`Detected platform: ${process.platform} (${process.arch})`);

  // Mutable references so watchConsent can stop & restart them
  let stopLog     = () => {};
  let stopProcess = () => {};
  let stopNetwork = () => {};
  let stopCanary  = () => {};
  let flushInterval = null;

  function startCollectors() {
    log("Starting collectors: system logs, processes, network, honeytoken canaries");
    stopLog     = startSystemLogCollector(handleEvent, handleError);
    stopProcess = startProcessCollector(handleEvent, handleError);
    stopNetwork = startNetworkCollector(handleEvent, handleError);
    stopCanary  = startHoneytokenCollector(handleEvent, handleError);
    if (!flushInterval) {
      flushInterval = setInterval(() => transport.flush(), config.batchIntervalMs);
    }
  }

  function pauseCollectors() {
    log("Pausing all collectors and telemetry flush — device access permission revoked/pending.");
    if (flushInterval) {
      clearInterval(flushInterval);
      flushInterval = null;
    }
    stopLog();     stopLog     = () => {};
    stopProcess(); stopProcess = () => {};
    stopNetwork(); stopNetwork = () => {};
    stopCanary();  stopCanary  = () => {};
  }

  if (permissionGranted) {
    startCollectors();
  } else {
    log("⚠️ Agent connected in STANDBY mode. Host monitoring is paused until permission is granted.");
  }

  // Watch consent file every 3s — stop or restart collectors live
  const stopConsentWatch = watchConsent({
    onRevoke: () => {
      pauseCollectors();
    },
    onGrant: () => {
      startCollectors();
    },
  });

  function shutdown() {
    log("Shutting down...");
    stopConsentWatch();
    if (flushInterval) clearInterval(flushInterval);
    stopLog();
    stopProcess();
    stopNetwork();
    stopCanary();
    transport.stop();
    process.exit(0);
  }

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main();
