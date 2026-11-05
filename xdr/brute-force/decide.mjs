
const PATTERNS = Object.freeze([
  {
    name: '동일 출발 주소의 반복 로그인 실패',
    condition: '짧은 시간 동안 같은 출발 주소에서 로그인 실패가 반복됨',
    evidence: 'MITRE ATT&CK T1110.001 Password Guessing',
  },
  {
    name: '여러 계정 대상 비밀번호 스프레이',
    condition: '같은 출발 주소에서 여러 계정에 공통 비밀번호 시도',
    evidence: 'MITRE ATT&CK T1110.003 Password Spraying',
  },
]);

export function decide(alert) {
  const data = alert?.data ?? {};
  const rule = alert?.rule ?? {};
  const description =
    typeof rule.description === 'string' ? rule.description : '';

  const level = Number(rule.level);
  const count = Number(data.count);
  const validCount = data.count !== undefined &&
    data.count !== null && data.count !== '' &&
    Number.isFinite(count) && count >= 0;

  const hasSource = typeof data.srcip === 'string' &&
    data.srcip.trim().length > 0;

  const hasAccount = typeof data.srcuser === 'string' &&
    data.srcuser.trim().length > 0;

  const failure = /로그인 실패|비밀번호.*실패|실패.*건/.test(description);
  const success = /성공했습니다|뒤에 성공|뒤 성공|로그아웃|세션 유지|상태가 유지|화면이 열렸/.test(description);
  const multipleAccounts =
    /여러 계정|계정 이름을 바꿔|서로 다른 계정|계정 20개/.test(description);
  const samePassword =
    /같은 비밀번호/.test(description);

  const shortWindow =
    /[1-5]분\s*(안|동안)|[1-5]분\s*이내/.test(description);

  const repeated =
    failure && validCount && count >= 15;

  let confidence = 0;
  let pattern = null;

// 반복 실패 후 성공은 차단하지 않고 추가 확인 대상으로 분류합니다.
if (
  hasSource &&
  hasAccount &&
  success &&
  failure &&
  validCount &&
  count >= 4 &&
  count <= 6
) {
  return {
    action: 'alert',
    confidence: 0.55,
    reason: PATTERNS[0].name,
  };
}

  if (hasSource && hasAccount && !success) {
    if (multipleAccounts && samePassword) {
      confidence = level >= 10 ? 0.98 : 0.82;
      pattern = PATTERNS[1];
    } else if (repeated && (shortWindow || level >= 10)) {
      confidence = count >= 30 && level >= 10 ? 0.95 : 0.87;
      pattern = PATTERNS[0];
    } else if (multipleAccounts && failure) {
      confidence = 0.72;
      pattern = PATTERNS[1];
    } else if (failure && validCount && count >= 3) {
      confidence = level >= 8 ? 0.65 : 0.55;
      pattern = PATTERNS[0];
    }
  }

  const action =
    confidence >= 0.85 ? 'block' :
    confidence >= 0.5 ? 'alert' : 'record';

  return {
    action,
    confidence,
    reason: pattern?.name ?? '무차별 로그인 공격 패턴 근거 부족',
  };
}
