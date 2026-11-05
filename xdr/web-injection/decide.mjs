
/**
 * XDR-02: 웹 주입 공격 탐지
 * MITRE ATT&CK T1190
 * 독립 실행형 판정기: 외부 import, 파일 및 네트워크 접근 없음
 */

const PATTERNS = Object.freeze([
  {
    name: 'SQL 주입 시도',
    condition: '요청 인자의 SQL 구문 조작 징후와 반복 여부',
    evidence: 'T1190: 외부 공개 애플리케이션의 SQL 주입 취약점 악용',
    test: /SQL 구문|SQL 표식|데이터베이스 조회를 이어 붙이는/,
  },
  {
    name: '스크립트 삽입 시도',
    condition: '스크립트 삽입 표기와 반복 여부',
    evidence: 'T1190: 외부 공개 애플리케이션의 입력 처리 취약점 악용',
    test: /스크립트 삽입|스크립트 표식/,
  },
  {
    name: '경로 탐색 시도',
    condition: '상위 경로 이동 표기와 반복 여부',
    evidence: 'T1190: 외부 공개 애플리케이션의 경로 처리 취약점 악용',
    test: /경로 이탈|경로를 여러 단계 거슬러/,
  },
  {
    name: '명령 구분자 반복 주입 시도',
    condition: '명령 구분자 사용 징후와 동일 출발 주소의 반복 여부',
    evidence: 'T1190: 외부 공개 애플리케이션의 명령 주입 취약점 악용',
    test: /명령 구분자/,
  },
]);

export function decide(alert) {
  const rule = alert?.rule ?? {};
  const data = alert?.data ?? {};

  const description =
    typeof rule.description === 'string' ? rule.description : '';

  const level = Number(rule.level);
  const count = Number(data.count);

  const validLevel = Number.isFinite(level);
  const validCount =
    data.count !== undefined &&
    data.count !== null &&
    data.count !== '' &&
    Number.isFinite(count) &&
    count >= 0;

  const hasSource =
    typeof data.srcip === 'string' &&
    data.srcip.trim().length > 0;

  const hasUrl =
    typeof data.url === 'string' &&
    data.url.trim().length > 0;

  const matched = PATTERNS.find(p => p.test.test(description));

  const repeated =
    /반복|연속|번갈아|번 들어왔|번 나왔|번에 있습니다/.test(
      description
    );

  const confirmed =
    hasSource &&
    hasUrl &&
    validLevel &&
    validCount &&
    count >= 8 &&
    level >= 10 &&
    repeated &&
    matched !== undefined;

  if (confirmed) {
    return {
      action: 'block',
      confidence: level >= 12 ? 0.98 : 0.9,
      reason: matched?.name ?? '명령 구분자 반복 주입 시도',
    };
  }

  // 단발성 이상 요청은 차단하지 않고 추가 확인합니다.
  if (
    hasSource &&
    hasUrl &&
    validLevel &&
    validCount &&
    count >= 1 &&
    level >= 5
  ) {
    return {
      action: 'alert',
      confidence: 0.55,
      reason: matched?.name ?? '웹 요청 이상 징후 확인 필요',
    };
  }

  return {
    action: 'record',
    confidence: 0,
    reason: '웹 주입 공격 패턴 근거 부족',
  };
}
