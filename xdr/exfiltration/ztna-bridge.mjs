import { checkTemporaryDeny } from './respond.mjs';
import { decide as ztnaDecide } from '../../src/decider.mjs';

// Educational adapter ONLY, not connected to the live ALEPH SDP runtime.
// The ALEPH v1 request does not include a trusted destination address or
// a Wazuh agent mapping. The caller must provide both from trusted telemetry,
// never directly from browser input or an unverified network parameter.
export async function decideWithXdr(request, verifiedFlow, now = Date.now()) {
  const base = await ztnaDecide(request);

  // Preserve all existing denial, step-up and resource-zone decisions.
  if (base.decision !== 'allow') return base;

  const deny = checkTemporaryDeny(
    verifiedFlow?.agentName, verifiedFlow?.destinationIp, now,
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
