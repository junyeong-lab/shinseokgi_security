
import { checkTemporaryDeny } from './respond.mjs';
import { decide as ztnaDecide } from '../../src/decider.mjs';

// 학습용 연결 모듈입니다.
// sourceIp는 실습 환경에서 별도로 전달하는 값이며,
// 실제 ALEPH SDP 요청에 포함된 필드가 아닙니다.
export async function decideWithXdr(request, sourceIp, now = Date.now()) {
  const rule = checkTemporaryDeny(sourceIp, now);

  if (rule) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'xdr_temporary_deny',
      ruleIds: [rule.ruleId],
    };
  }

  // 차단 대상이 아니면 기존 ZTNA 판정 결과를 그대로 사용합니다.
  return ztnaDecide(request);
}
