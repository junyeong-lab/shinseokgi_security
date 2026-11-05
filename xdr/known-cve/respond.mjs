import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decide } from './decide.mjs';

// XDR-03 learning-only response layer; not the official ALEPH SDP engine.
const LOG_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'alerts.log');
const TTL_MS = 15 * 60 * 1000;
const denyRules = new Map();

const validIp = value => typeof value === 'string'
  && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
  && value.split('.').every(part => Number(part) <= 255);
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/u.test(value)
  ? value : 'unknown';

export async function respond(alert, now = Date.now()) {
  const result = decide(alert);
  const alertId = safeId(alert?.id);

  for (const [ip, rule] of denyRules) {
    if (rule.expiresAtMs <= now) denyRules.delete(ip);
  }

  // A high-confidence explicit request payload and known source are required.
  // A normal event or an alert-only record must never create a deny rule.
  if (result.action === 'block' && result.confidence >= 0.85
      && validIp(alert?.data?.srcip) && alertId !== 'unknown') {
    denyRules.set(alert.data.srcip, {
      ruleId: 'xdr.known_cve.temporary_deny',
      expiresAtMs: now + TTL_MS,
      expiresAt: new Date(now + TTL_MS).toISOString(),
      evidenceAlertId: alertId,
      reason: result.reason,
    });
  }

  // No HTTP content, user names, credentials, account or memo contents in logs.
  const log = JSON.stringify({
    at: new Date(now).toISOString(), moduleKey: 'known-cve',
    alertId, action: result.action, confidence: result.confidence,
    reason: result.reason,
  });
  await appendFile(LOG_PATH, log + '\n', 'utf8');
  return result;
}

export function checkTemporaryDeny(ip, now = Date.now()) {
  if (!validIp(ip)) return null;
  const rule = denyRules.get(ip);
  if (!rule || rule.expiresAtMs <= now) {
    if (rule) denyRules.delete(ip);
    return null;
  }
  return { ...rule };
}
