/**
 * ALEPH XDR offline educational classifier (privilege).
 * Independent pure function: no imports, I/O, network, or external state.
 * Blocks are high-confidence candidates, not actual ZTNA enforcement.
 */
const PATTERNS = Object.freeze([
  {
    "name": "예상 밖 관리자 그룹 변경",
    "condition": "관리자 그룹 추가 및 원격 접속·다계정·명령 실행 등 추가 정황",
    "evidence": "MITRE ATT&CK T1078: Valid Accounts",
    "reference": "https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "승격 직후 관리자 명령",
    "condition": "관리자 권한을 얻은 직후 관리자 명령 실행",
    "evidence": "T1078 계정 권한 오남용 단서이며 T1068의 취약점 악용 사실을 별도 입증할 필요 있음",
    "reference": "https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "이상 세션·권한 전환",
    "condition": "낯선 출발지의 관리자 세션 전환 또는 다른 계정 권한으로 관리자 명령",
    "evidence": "T1078은 계정 남용 및 추가 접근 권한 확보를 설명",
    "reference": "https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "비정상 관리자 명령",
    "condition": "평소와 다른 시간 및 낯선 주소에서 고권한 명령",
    "evidence": "T1078에 따른 유효 계정 오용 조사",
    "reference": "https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "권한 변경 정황 확인 필요",
    "condition": "취소된 권한 요청·단독 관리자 명령·비관리자 그룹 변경 등",
    "evidence": "T1068은 실제 소프트웨어 취약점 악용을 뜻하므로 UAC 표시·관리자 명령만으로 악용을 확정하지 않음",
    "reference": "https://attack.mitre.org/techniques/T1068/"
  }
].map(pattern => Object.freeze(pattern)));
export function decide(alert) {
  const rule = alert && typeof alert === 'object' ? alert.rule : null;
  const data = alert && typeof alert === 'object' ? alert.data : null;
  const level = rule?.level;
  const description = typeof rule?.description === 'string' ? rule.description.slice(0, 2048) : '';
  const source = typeof data?.srcip === 'string' ? data.srcip.trim() : '';
  const tagged = Array.isArray(rule?.mitre) && rule.mitre.some(id => id === 'T1078' || id === 'T1068');
  const adminGroup = typeof data?.group === 'string' && data.group.toLowerCase() === 'administrators';
  const added = /관리자 그룹에 (?:추가|들어가)|관리자 그룹 추가|다시 관리자(?:로)? 들어왔/.test(description);
  const granted = adminGroup && (added || /계정 \d+개가 관리자 그룹에 추가/.test(description));
  const command = /관리자 명령|권한 명령|명령 실행/.test(description);
  const recent = /방금 관리자가 된|곧바로|그룹 추가와 명령 실행/.test(description);
  const abnormal = /처음 보는 주소|원격 주소|수업 시간 밖|업무처럼 보이지 않는 시각/.test(description);
  const session = /관리자 권한으로 바뀌/.test(description) && /처음/.test(description);
  const impersonation = /다른 계정의 권한으로 관리자 명령/.test(description);
  const regrant = /다시 관리자로 들어왔/.test(description);
  const benign = /취소됐|관리자 그룹은 아닙니다|실패 1건|변경은 없습니다|명령은 없습니다|조회한 뒤|평소 주소/.test(description);
  let match = -1;
  if (source && typeof level === 'number' && Number.isFinite(level) && level >= 10 && tagged && !benign) {
    if (granted && (abnormal || command || Number(data?.count) >= 2 || regrant || /평범한 계정/.test(description))) match = 0;
    else if (command && recent) match = 1;
    else if (session || impersonation) match = 2;
    else if (command && abnormal) match = 3;
  }
  if (match >= 0) return { action: 'block', confidence: 0.93, reason: PATTERNS[match].name };
  if (source && typeof level === 'number' && Number.isFinite(level) &&
      level >= 5 && tagged && /권한|관리자|그룹|명령|세션|계정 종류/.test(description)) {
    return { action: 'alert', confidence: 0.61, reason: PATTERNS[4].name };
  }
  return { action: 'record', confidence: 0.05, reason: '비인가 권한 상승 근거 부족' };
}
