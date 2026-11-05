/**
 * XDR-03: CVE-2021-44228 / MITRE ATT&CK T1190
 * Deterministic, self-contained classifier for educational Wazuh alerts.
 * No file access, network requests, imported modules or side effects.
 * Pattern names and evidence match xdr/known-cve/patterns.json.
 */
const PATTERNS = Object.freeze([
  {
    "name": "JNDI 원격 조회 구문",
    "condition": "요청 URL 인자나 User-Agent에 완결된 ${jndi:<프로토콜>://...} 조회 표현식이 직접 포함된 경우에만 명확한 악용 후보로 분류",
    "evidence": "CVE-2021-44228(Log4Shell)의 공격 입력은 로그 처리에 JNDI 원격 조회 표현식을 전달하는 방식이며 MITRE ATT&CK T1190은 공개 애플리케이션의 취약점 악용을 설명함."
  },
  {
    "name": "CVE-2021-44228 탐지·점검 징후",
    "condition": "Wazuh T1190 경보와 CVE-2021-44228 언급, 검사·점검·조회 형태 단서가 함께 있지만 완결된 악용 구문은 확인되지 않은 경우",
    "evidence": "CVE-2021-44228 취약점 점검이나 명칭의 언급만으로 공격 실행을 확정할 수 없으며 T1190 관련 경보는 별도 확인이 필요함."
  },
  {
    "name": "불완전 JNDI·조회 구문 단서",
    "condition": "Wazuh T1190 경보에서 jndi, 조회 구문 일부, 중괄호 흔적 또는 잘린 조회 표기가 확인되지만 원격 조회 구문이 완결되지 않은 경우",
    "evidence": "Log4Shell의 특징적인 조회 표현식과 유사한 조각은 탐지 단서가 되지만 완결된 악용 근거가 없으면 차단 대신 경보로 분류함."
  },
  {
    "name": "취약점 스캐너·라이브러리 점검 단서",
    "condition": "Wazuh T1190 경보에서 취약점 검사 도구, 진단 경로 또는 로그 라이브러리 점검 흔적만 확인되는 경우",
    "evidence": "MITRE ATT&CK T1190 관련 취약점 탐색 행위는 보안 점검에서도 발생할 수 있으므로 단독 근거만으로 차단하지 않음."
  }
].map(item => Object.freeze(item)));
const DIRECT_JNDI = /\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop|corba|nis):\/\/[^}\s]{1,512}\}/iu;
const CVE_CONTEXT = /CVE[- ]2021[- ]44228|log4shell/iu;
const JNDI_FRAGMENT = /jndi|조회\s*(?:구문|형태)|중괄호|lookup[-_ ]?fragment|원격\s*조회/iu;
const TOOL_CONTEXT = /취약점|점검|스캐너|라이브러리|class[-_ ]?(?:check|browser)|cve[-_ ]?list|log[-_ ]?library/iu;

export function decide(alert) {
  const data = alert && typeof alert === 'object' ? alert.data : null;
  const rule = alert && typeof alert === 'object' ? alert.rule : null;
  const source = typeof data?.srcip === 'string' ? data.srcip.trim() : '';
  const level = rule?.level;
  const validLevel = typeof level === 'number' && Number.isFinite(level);
  const url = typeof data?.url === 'string' ? data.url.slice(0, 4096) : '';
  const agent = typeof data?.useragent === 'string' ? data.useragent.slice(0, 4096) : '';
  const description = typeof rule?.description === 'string'
    ? rule.description.slice(0, 4096) : '';
  const tagged = Array.isArray(rule?.mitre) && rule.mitre.includes('T1190');

  // Only unmistakable request-side material can trigger blocking.
  if (source && validLevel && level >= 10 && (DIRECT_JNDI.test(url) || DIRECT_JNDI.test(agent))) {
    return {
      action: 'block',
      confidence: tagged ? 0.98 : 0.87,
      reason: PATTERNS[0].name,
    };
  }

  // A CVE reference or incomplete marker is a review signal, not a ban.
  if (source && validLevel && level >= 5 && tagged) {
    const evidence = description + '\n' + url + '\n' + agent;
    let pattern = null;
    if (CVE_CONTEXT.test(evidence)) pattern = PATTERNS[1];
    else if (JNDI_FRAGMENT.test(evidence)) pattern = PATTERNS[2];
    else if (TOOL_CONTEXT.test(evidence)) pattern = PATTERNS[3];
    if (pattern) {
      return { action: 'alert', confidence: 0.62, reason: pattern.name };
    }
  }

  return {
    action: 'record',
    confidence: 0.05,
    reason: 'CVE-2021-44228 악용 근거 부족',
  };
}
