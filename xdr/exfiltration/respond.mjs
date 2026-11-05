import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decide } from './decide.mjs';

// XDR-06 educational response layer: no live ALEPH SDP policy modification.
const LOG_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'alerts.log');
const TTL_MS = 15 * 60 * 1000;
const destinationDenials = new Map();

const validAgentName = value => typeof value === 'string' &&
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/u.test(value);
const validIp = value => typeof value === 'string' &&
  /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) &&
  value.split('.').every(part => Number(part) <= 255);
const safeId = value => typeof value === 'string' &&
  /^[A-Za-z0-9_-]{1,80}$/u.test(value) ? value : 'unknown';

// Scope a destination deny to the affected PC, so other normal PCs that
// happen to use the same destination are not denied on this evidence alone.
const keyFor = (agentName, destinationIp) =>
  validAgentName(agentName) && validIp(destinationIp)
    ? JSON.stringify([agentName, destinationIp]) : null;

export async function respond(alert, now = Date.now()) {
  const decision = decide(alert);
  const evidenceAlertId = safeId(alert?.id);
  const key = keyFor(alert?.agent?.name, alert?.data?.dstip);

  for (const [item, rule] of destinationDenials) {
    if (rule.expiresAtMs <= now) destinationDenials.delete(item);
  }

  // Block the DESTINATION, never the sending srcip. Low-confidence and
  // normal events create no deny entry.
  if (decision.action === 'block' && decision.confidence >= 0.85 &&
      key && evidenceAlertId !== 'unknown') {
    destinationDenials.set(key, {
      ruleId: 'xdr.exfiltration.temporary_destination_deny',
      expiresAtMs: now + TTL_MS,
      expiresAt: new Date(now + TTL_MS).toISOString(),
      evidenceAlertId,
      reason: decision.reason,
    });
  }

  // No raw destination/source IP, account, contents, names, or secrets in logs.
  const line = JSON.stringify({
    at: new Date(now).toISOString(),
    moduleKey: 'exfiltration',
    alertId: evidenceAlertId,
    action: decision.action,
    confidence: decision.confidence,
    reason: decision.reason,
  });
  await appendFile(LOG_PATH, line + '\n', 'utf8');
  return decision;
}

export function checkTemporaryDeny(verifiedAgentName, verifiedDestinationIp, now = Date.now()) {
  const key = keyFor(verifiedAgentName, verifiedDestinationIp);
  if (!key) return null;
  const rule = destinationDenials.get(key);
  if (!rule || rule.expiresAtMs <= now) {
    if (rule) destinationDenials.delete(key);
    return null;
  }
  return { ...rule };
}
