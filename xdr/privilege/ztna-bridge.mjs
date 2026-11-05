import { checkTemporaryDeny } from './respond.mjs';
import { decide as ztnaDecide } from '../../src/decider.mjs';

// Teaching-only integration, not an actual ALEPH SDP session-revocation API.
// The existing ALEPH request has subjectId, not a verified Wazuh username.
// The caller MUST supply a trusted session-to-Wazuh agent/account mapping.
// Never accept browser-supplied usernames or equate subjectId to srcuser.
export async function decideWithXdr(request, verifiedAccount, now = Date.now()) {
  const base = await ztnaDecide(request);
  // Existing deny / step-up must never be replaced by the XDR module.
  if (base.decision !== 'allow') return base;

  const deny = checkTemporaryDeny(
    verifiedAccount?.agentName, verifiedAccount?.accountName, now,
  );
  if (!deny) return base;

  return {
    schema: base.schema,
    requestId: base.requestId,
    decision: 'deny',
    reasonCode: 'xdr_temporary_deny',
    ruleIds: [deny.ruleId],
  };
}
