import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/persistence.json', import.meta.url);

// 출력 항목은 시각·출발 주소·계정·규칙 수준·설명으로 제한합니다.
// 비밀값이 포함된 입력은 출력 전에 가리고, 원본 경보는 변경하지 않습니다.
function safeText(value, maxLength = 160) {
  if (typeof value !== 'string') return '-';

  const redacted = value
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/giu, '[REDACTED]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+/giu, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b/gu, '[REDACTED]')
    .replace(/\b(?:sb_secret_|sk-)[A-Za-z0-9_-]{12,}\b/giu, '[REDACTED]')
    .replace(/\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session)\s*[:=]\s*(?:"[^"]*"|'[^']*'|\S+)/giu, '[REDACTED]')
    .replace(/[\u0000-\u001f\u007f]/gu, ' ')
    .trim();

  return redacted.slice(0, maxLength) || '-';
}

export function extractAlert(alert) {
  return {
    timestamp: safeText(alert?.timestamp, 40),
    sourceAddress: safeText(alert?.data?.srcip, 45),
    account: safeText(alert?.data?.srcuser, 80),
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description, 160),
  };
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'persistence' || !Array.isArray(fixture.alerts)) {
    throw new Error('persistence Wazuh 경보 묶음 형식이 아닙니다.');
  }
  return fixture.alerts.map(extractAlert);
}

// 단독 실행 전용: 원본 건수와 안전한 출력 줄 수를 비교합니다.
// 이 모듈은 ZTNA 판정기나 XDR decide.mjs에서 호출하지 않습니다.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rows = await readAlerts();
  if (fixture.alerts.length !== rows.length) {
    console.error('경보 건수와 추출 건수가 일치하지 않습니다.');
    process.exitCode = 1;
  } else {
    for (const row of rows) console.log(JSON.stringify(row));
    console.error('경보 건수: ' + fixture.alerts.length + ', 추출 줄 수: ' + rows.length);
  }
}
