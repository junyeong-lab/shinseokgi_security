import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decide } from './decide.mjs';

// XDR-04 educational isolation candidates only, not the live ALEPH engine.
const LOG_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'alerts.log');
const TTL_MS = 15 * 60 * 1000;
const isolatedPcs = new Map();

// Wazuh agent.name identifies a PC; srcip in these alerts is the remote source.
const validAgent = value => typeof value === 'string'
  && /^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$/u.test(value);
const safeId = value => typeof value === 'string'
  && /^[A-Za-z0-9_-]{1,80}$/u.test(value) ? value : 'unknown';

export async function respond(alert, now = Date.now()) {
  const result = decide(alert);
  const evidenceAlertId = safeId(alert?.id);
  const agentName = alert?.agent?.name;

  for (const [name, rule] of isolatedPcs) {
    if (rule.expiresAtMs <= now) isolatedPcs.delete(name);
  }

  // Only confirmed high-confidence attacks can isolate the affected PC.
  if (result.action === 'block' && result.confidence >= 0.85
      && validAgent(agentName) && evidenceAlertId !== 'unknown') {
    isolatedPcs.set(agentName, {
      ruleId: 'xdr.persistence.temporary_isolation',
      expiresAtMs: now + TTL_MS,
      expiresAt: new Date(now + TTL_MS).toISOString(),
      evidenceAlertId,
      reason: result.reason,
    });
  }

  // Deliberately omit device identity, IP, account, path, and raw payloads.
  const line = JSON.stringify({
    at: new Date(now).toISOString(),
    moduleKey: 'persistence',
    alertId: evidenceAlertId,
    action: result.action,
    confidence: result.confidence,
    reason: result.reason,
  });
  await appendFile(LOG_PATH, line + '\n', 'utf8');
  return result;
}

export function checkTemporaryDeny(verifiedAgentName, now = Date.now()) {
  if (!validAgent(verifiedAgentName)) return null;
  const rule = isolatedPcs.get(verifiedAgentName);
  if (!rule || rule.expiresAtMs <= now) {
    if (rule) isolatedPcs.delete(verifiedAgentName);
    return null;
  }
  return { ...rule };
}
