/**
 * ALEPH XDR offline educational classifier (exfiltration).
 * Independent pure function: no imports, I/O, network, or external state.
 * Blocks are high-confidence candidates, not actual ZTNA enforcement.
 */
const PATTERNS = Object.freeze([
  {
    "name": "처음 보는 목적지로 대량 반출",
    "condition": "50MB 이상의 대량 자료를 낯선 목적지로 보냈으며 추가 이상 징후 확인",
    "evidence": "MITRE ATT&CK T1048은 비C2 경로, T1041은 C2 통로의 정보 반출을 설명",
    "reference": "https://attack.mitre.org/techniques/T1048/"
  },
  {
    "name": "비정상 통로·시간대 대량 전송",
    "condition": "업무시간 외, 미사용 포트, 명령 통로 등의 대량 송신",
    "evidence": "MITRE ATT&CK T1041 Exfiltration Over C2 Channel",
    "reference": "https://attack.mitre.org/techniques/T1041/"
  },
  {
    "name": "반복·대량 파일 반출",
    "condition": "고용량 반복 송신·대량 파일 또는 자료실 전체 반출 정황",
    "evidence": "MITRE ATT&CK T1041/T1048 맥락에 따라 지속적인 파일 유출 신호 분석",
    "reference": "https://attack.mitre.org/techniques/T1041/"
  },
  {
    "name": "압축 후 낯선 목적지 전송",
    "condition": "압축 파일의 낯선 목적지 업로드 및 고용량 전송",
    "evidence": "압축은 단독 공격 근거가 아니며 목적지·실제 송신 여부를 확인",
    "reference": "https://attack.mitre.org/techniques/T1048/"
  },
  {
    "name": "반출 의심 추가 확인",
    "condition": "소량·실패·미전송 압축 준비 등 반출 확정 불가",
    "evidence": "전송량·파일 개수만으로 악성 반출 확정 불가",
    "reference": "https://attack.mitre.org/techniques/T1048/"
  }
].map(pattern => Object.freeze(pattern)));
export function decide(alert) {
  const rule = alert && typeof alert === 'object' ? alert.rule : null;
  const data = alert && typeof alert === 'object' ? alert.data : null;
  const level = rule?.level;
  const description = typeof rule?.description === 'string' ? rule.description.slice(0, 2048) : '';
  const source = typeof data?.srcip === 'string' ? data.srcip.trim() : '';
  const destination = typeof data?.dstip === 'string' ? data.dstip.trim() : '';
  const tagged = Array.isArray(rule?.mitre) && rule.mitre.some(id => id === 'T1041' || id === 'T1048');
  const amount = typeof data?.bytes === 'number' || typeof data?.bytes === 'string' ? Number(data.bytes) : NaN;
  const validAmount = Number.isFinite(amount) && amount >= 0;
  const large = validAmount && amount >= 50000000;
  const unknown = /처음 보는|외부 주소|처음.*목적지/.test(description);
  const abnormal = /수업 시간 밖|업무 시간 밖|평소에 쓰지 않던 포트|명령 통로/.test(description);
  const repeated = /\d+번 반복|\d+번입니다|연속/.test(description);
  const many = /자료실 전체|자료 \d+건|메모 묶음|파일 \d+개/.test(description) || Number(data?.files) >= 50;
  const compressed = /압축 파일/.test(description);
  const sent = /나갔|전송됐|복사됐|올라갔|전송이.*\d+번/.test(description);
  const failed = /실패|전송은 아직 없/.test(description);
  let match = -1;
  if (source && destination && typeof level === 'number' && Number.isFinite(level) &&
      level >= 10 && tagged && large && sent && !failed) {
    if (unknown && compressed) match = 3;
    else if (unknown && many) match = 0;
    else if (abnormal) match = 1;
    else if (repeated || many || unknown) match = 2;
  }
  if (match >= 0) return { action: 'block', confidence: 0.95, reason: PATTERNS[match].name };
  if (source && typeof level === 'number' && Number.isFinite(level) &&
      level >= 5 && tagged && (validAmount || compressed || /전송|압축|파일|자료|명령 통로/.test(description))) {
    return { action: 'alert', confidence: 0.6, reason: PATTERNS[4].name };
  }
  return { action: 'record', confidence: 0.05, reason: '비인가 자료 반출 근거 부족' };
}
