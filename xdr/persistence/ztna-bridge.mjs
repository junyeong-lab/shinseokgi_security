import { checkTemporaryDeny } from './respond.mjs';
import { decide as ztnaDecide } from '../../src/decider.mjs';

// Teaching-only adapter: verifiedAgentName MUST come from a trusted EDR device
// inventory mapping, not browser input. ALEPH's verified deviceId does not
// provide the Wazuh agent-name mapping; do not claim live SDP enforcement.
export async function decideWithXdr(request, verifiedAgentName, now = Date.now()) {
  const existing = await ztnaDecide(request);
  // Never relax or replace existing policy rules and step-up obligations.
  if (existing.decision !== 'allow') return existing;
  const isolation = checkTemporaryDeny(verifiedAgentName, now);
  if (!isolation) return existing;
  return {
    schema: existing.schema,
    requestId: existing.requestId,
    decision: 'deny',
    reasonCode: 'xdr_temporary_deny',
    ruleIds: [isolation.ruleId],
  };
}
