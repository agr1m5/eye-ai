/**
 * alertService.js — Server-side webhook alert dispatcher.
 *
 * Fires configured webhooks when high-severity findings arrive in real time.
 *
 * Supported channels:
 *   - Slack Incoming Webhook (SLACK_WEBHOOK_URL in server/.env)
 *   - Generic HTTP webhook (ALERT_WEBHOOK_URL in server/.env)
 *
 * Gracefully no-ops when no webhooks are configured — no crashes.
 *
 * Usage:
 *   import { dispatchCriticalAlert } from '../services/alertService.js';
 *   await dispatchCriticalAlert(threat);
 */
import { config } from '../config/env.js';

const TIMEOUT_MS = 5000;

/**
 * Build a Slack block-kit message payload for a critical threat.
 */
function buildSlackPayload(threat) {
  const sev = (threat.severity || 'critical').toUpperCase();
  const ip = threat.source?.ip || threat.source?.hostname || 'unknown';
  const type = threat.type || 'Unknown Threat';
  const desc = threat.description || 'No description available.';
  const ts = new Date(threat.createdAt || Date.now()).toUTCString();

  return {
    text: `🚨 *${sev} ALERT — ${type}*`,
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `🚨 ${sev}: ${type}`,
          emoji: true,
        },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Severity:*\n${sev}` },
          { type: 'mrkdwn', text: `*Source IP:*\n\`${ip}\`` },
          { type: 'mrkdwn', text: `*Detected At:*\n${ts}` },
          { type: 'mrkdwn', text: `*Threat ID:*\n\`${threat._id}\`` },
        ],
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Description:*\n${desc}` },
      },
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: '_Eye SOC | Automated Detection Pipeline_',
          },
        ],
      },
    ],
  };
}

/**
 * Build a generic JSON webhook payload.
 */
function buildGenericPayload(threat) {
  return {
    event:     'critical_threat',
    severity:  threat.severity,
    type:      threat.type,
    source:    threat.source,
    description: threat.description,
    threatId:  threat._id?.toString(),
    timestamp: new Date(threat.createdAt || Date.now()).toISOString(),
    source_system: 'eye-soc-v2',
  };
}

/**
 * Dispatch an alert for a critical (or high) finding to all configured channels.
 *
 * @param {object} threat - Mongoose Threat document or plain object
 */
export async function dispatchCriticalAlert(threat) {
  const slackUrl = config.slackWebhookUrl;
  const genericUrl = config.alertWebhookUrl;

  // Nothing to do if no channels configured
  if (!slackUrl && !genericUrl) return;

  const dispatches = [];

  if (slackUrl) {
    dispatches.push(
      fetch(slackUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(buildSlackPayload(threat)),
        signal:  AbortSignal.timeout(TIMEOUT_MS),
      })
        .then((r) => {
          if (!r.ok) console.warn(`[AlertService] Slack webhook returned ${r.status}`);
          else console.log(`[AlertService] ✅ Slack alert sent for ${threat.type}`);
        })
        .catch((err) => console.error(`[AlertService] Slack webhook error: ${err.message}`))
    );
  }

  if (genericUrl) {
    dispatches.push(
      fetch(genericUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(buildGenericPayload(threat)),
        signal:  AbortSignal.timeout(TIMEOUT_MS),
      })
        .then((r) => {
          if (!r.ok) console.warn(`[AlertService] Generic webhook returned ${r.status}`);
          else console.log(`[AlertService] ✅ Generic webhook sent for ${threat.type}`);
        })
        .catch((err) => console.error(`[AlertService] Generic webhook error: ${err.message}`))
    );
  }

  // Fire-and-forget in parallel; don't block finding ingestion
  await Promise.allSettled(dispatches);
}
