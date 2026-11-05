/**
 * ALEPH XDR offline educational classifier (persistence).
 * Independent pure function: no imports, I/O, network, or external state.
 * Blocks are high-confidence candidates, not actual ZTNA enforcement.
 */
const PATTERNS = Object.freeze([
  {
    "name": "서명 없는 서비스 등록·변조",
    "condition": "신규 또는 변경된 서비스 실행 파일의 서명 부재와 임시 폴더/등록 정황",
    "evidence": "MITRE ATT&CK T1543: Create or Modify System Process",
    "reference": "https://attack.mitre.org/techniques/T1543/"
  },
  {
    "name": "비정상 예약 작업 실행",
    "condition": "임시 폴더 실행 파일을 참조하는 처음 보는 예약 작업 또는 비정상 시각 예약 작업",
    "evidence": "MITRE ATT&CK T1053: Scheduled Task/Job",
    "reference": "https://attack.mitre.org/techniques/T1053/"
  },
  {
    "name": "시작 프로그램 등록 이상",
    "condition": "평소 목록에 없는 시작 프로그램 등록과 실행 파일 경로 확인",
    "evidence": "시작 폴더 자동 실행은 지속성 단서이나 T1543의 서비스 메커니즘과 동일하다고 단정하지 않음",
    "reference": "https://attack.mitre.org/techniques/T1543/"
  },
  {
    "name": "복합 자동실행 지속성",
    "condition": "예약 작업 및 시작 프로그램이 동일 임시 실행 파일을 호출",
    "evidence": "MITRE ATT&CK T1053과 운영체제 자동실행 지속성의 복합 단서",
    "reference": "https://attack.mitre.org/techniques/T1053/"
  },
  {
    "name": "지속성 변경 추가 확인",
    "condition": "T1543/T1053 경보의 서비스·예약 작업 등 미확정 단서",
    "evidence": "정상 관리도 예약 작업 및 서비스를 생성하므로 단독 징후만으로 차단하지 않음",
    "reference": "https://attack.mitre.org/techniques/T1053/"
  }
].map(pattern => Object.freeze(pattern)));
export function decide(alert) {
  const rule = alert && typeof alert === 'object' ? alert.rule : null;
  const data = alert && typeof alert === 'object' ? alert.data : null;
  const level = rule?.level;
  const description = typeof rule?.description === 'string' ? rule.description.slice(0, 2048) : '';
  const path = typeof data?.path === 'string' ? data.path.slice(0, 1024) : '';
  const source = typeof data?.srcip === 'string' ? data.srcip.trim() : '';
  const mitre = Array.isArray(rule?.mitre) ? rule.mitre : [];
  const tagged = mitre.includes('T1543') || mitre.includes('T1053');
  const service = /서비스/.test(description);
  const task = /예약 작업/.test(description);
  const startup = /시작 (?:폴더|프로그램|항목)|시작 폴더/.test(description);
  const temp = /\\(?:AppData\\Local\\Temp|Temp)\\/i.test(path);
  const unsigned = /서명 없는|서명이 없|서명은 확인되지 않/.test(description);
  const unknown = /평소 목록에 없는|처음 보는|임의 문자열/.test(description);
  const changed = /실행 파일이 바뀌|서비스 등록/.test(description);
  const repeated = /연속/.test(description) && Number(data?.count) >= 3;
  const outside = /수업 시간 밖/.test(description);
  const combined = startup && task && temp && /같은 임시 파일/.test(description);
  const serviceRisk = service && ((unsigned && (temp || changed || repeated)) ||
    (unknown && temp && /등록/.test(description)));
  const taskRisk = task && temp && (unknown || outside);
  const startRisk = startup && unknown && (/\\Startup\\/i.test(path) || temp) && /추가/.test(description);
  let match = -1;
  if (source && typeof level === 'number' && Number.isFinite(level) && level >= 10 && tagged) {
    if (combined) match = 3;
    else if (serviceRisk) match = 0;
    else if (taskRisk) match = 1;
    else if (startRisk) match = 2;
  }
  if (match >= 0) return { action: 'block', confidence: 0.94, reason: PATTERNS[match].name };
  if (source && typeof level === 'number' && Number.isFinite(level) &&
      level >= 5 && tagged && (service || task || startup || /임시 폴더/.test(description))) {
    return { action: 'alert', confidence: 0.6, reason: PATTERNS[4].name };
  }
  return { action: 'record', confidence: 0.05, reason: '지속성 악용 근거 부족' };
}
