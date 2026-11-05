import { checkTemporaryDeny } from './respond.mjs';
import { decide as ztnaDecide } from '../../src/decider.mjs';

// XDR-03 educational bridge only. The ALEPH SDP request contract contains
// no source IP, so a verified sourceIp must be supplied separately.
// Do not replace src/decider.mjs or claim this bridge is deployed to ALEPH.
export async function decideWithXdr(request, sourceIp, now = Date.now()) {
  const deny = checkTemporaryDeny(sourceIp, now);
  if (deny) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'xdr_temporary_deny',
      ruleIds: [deny.ruleId],
    };
  }
  return ztnaDecide(request);
}
