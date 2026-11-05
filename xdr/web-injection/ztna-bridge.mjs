
import { checkTemporaryDeny } from './respond.mjs';
import { decide as ztnaDecide } from '../../src/decider.mjs';

// XDR-02 학습용 ZTNA 연결 모듈
// sourceIp는 실습용으로 별도 전달합니다.
// 실제 ALEPH SDP 요청 계약에는 출발 IP가 없습니다.

export async function decideWithXdr(request, sourceIp, now = Date.now()) {
  const rule = checkTemporaryDeny(sourceIp, now);

  // 유효한 XDR 임시 차단 규칙이 있을 때만 추가 거부합니다.
  if (rule) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'xdr_temporary_deny',
      ruleIds: [rule.ruleId],
    };
  }

  // 차단 대상이 아니면 기존 ZTNA 정책을 그대로 적용합니다.
  return ztnaDecide(request);
}
