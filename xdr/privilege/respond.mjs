import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decide } from './decide.mjs';

// XDR-05 educational response layer; never writes to the live ALEPH SDP policy.
const LOG_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'alerts.log');
const TTL_MS = 15 * 60 * 1000;
const revokedAccounts = new Map();

const safePrincipal = value => typeof value === 'string'
  && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/u.test(value);
const safeAlertId = value => typeof value === 'string'
  && /^[a-zA-Z0-9_-]{1,80}$/u.test(value) ? value : 'unknown';

// Wazuh account names are only meaningful for the reporting endpoint.
// Combining agent and account avoids revoking a same-named normal account on another PC.
const accountKey = (agentName, accountName) =>
  safePrincipal(agentName) && safePrincipal(accountName)
    ? JSON.stringify([agentName, accountName]) : null;

export async function respond(alert, now = Date.now()) {
  const decision = decide(alert);
  const alertId = safeAlertId(alert?.id);
  const key = accountKey(alert?.agent?.name, alert?.data?.srcuser);

  for (const [scope, rule] of revokedAccounts) {
    if (rule.expiresAtMs <= now) revokedAccounts.delete(scope);
  }

  // Only confirmed high-confidence escalation with usable verified evidence
  // creates a temporary account-session revocation candidate.
  if (decision.action === 'block' && decision.confidence >= 0.85
      && key && alertId !== 'unknown') {
    revokedAccounts.set(key, {
      ruleId: 'xdr.privilege.temporary_session_revoke',
      expiresAtMs: now + TTL_MS,
      expiresAt: new Date(now + TTL_MS).toISOString(),
      evidenceAlertId: alertId,
      reason: decision.reason,
    });
  }

  // No account, IP, session identifier, credentials, raw text or memo content.
  await appendFile(LOG_PATH, JSON.stringify({
    at: new Date(now).toISOString(),
    moduleKey: 'privilege',
    alertId, action: decision.action,
    confidence: decision.confidence, reason: decision.reason,
  }) + '\n', 'utf8');
  return decision;
}

export function checkTemporaryDeny(verifiedAgentName, verifiedAccountName, now = Date.now()) {
  const key = accountKey(verifiedAgentName, verifiedAccountName);
  if (!key) return null;
  const rule = revokedAccounts.get(key);
  if (!rule || rule.expiresAtMs <= now) {
    if (rule) revokedAccounts.delete(key);
    return null;
  }
  return { ...rule };
}
