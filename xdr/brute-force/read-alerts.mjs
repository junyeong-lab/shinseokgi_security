
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/brute-force.json', import.meta.url);
const fixture = JSON.parse(readFileSync(fileURLToPath(fixtureUrl), 'utf8'));

if (!Array.isArray(fixture.alerts)) {
  throw new Error('Wazuh alerts 배열을 찾을 수 없습니다.');
}

// 허용된 문자만 출력하고, 비밀값으로 보이는 문자열은 숨깁니다.
function safeText(value) {
  if (typeof value !== 'string') return '-';

  const secret =
    /password|passwd|secret|token|api.?key|authorization|bearer/i;

  if (secret.test(value)) return '[REDACTED]';

  return value
    .replace(/[\r\n\t|]/g, ' ')
    .replace(/[^\p{L}\p{N} .,:/@+_-]/gu, '');
}

const extracted = fixture.alerts.map((alert) => ({
  timestamp: safeText(alert.timestamp),
  sourceAddress: safeText(alert.data?.srcip),
  account: safeText(alert.data?.srcuser),
  ruleLevel: Number.isFinite(alert.rule?.level)
    ? alert.rule.level
    : '-',
  description: safeText(alert.rule?.description),
}));

for (const item of extracted) {
  console.log(
    [
      item.timestamp,
      item.sourceAddress,
      item.account,
      item.ruleLevel,
      item.description,
    ].join(' | ')
  );
}

console.error(
  `Alert count: ${fixture.alerts.length}, Extracted lines: ${extracted.length}`
);

if (fixture.alerts.length !== extracted.length) {
  process.exitCode = 1;
}
