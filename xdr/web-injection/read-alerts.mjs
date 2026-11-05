
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const currentDir = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(currentDir, '..', 'fixtures', 'web-injection.json');

// 경보 안의 비밀값이나 제어 문자는 출력하지 않습니다.
function safeText(value, maxLength = 160) {
  if (typeof value !== 'string') return '-';

  const redacted = value
    .replace(/(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+/gi, '[REDACTED]')
    .replace(/[\r\n\t\x00-\x1f\x7f]/g, ' ');

  return redacted.slice(0, maxLength);
}

export function extractAlert(alert) {
  return {
    timestamp: safeText(alert?.timestamp, 40),
    sourceIp: safeText(alert?.data?.srcip, 45),
    account: safeText(alert?.data?.srcuser, 80),
    ruleLevel: Number.isFinite(Number(alert?.rule?.level))
      ? Number(alert.rule.level)
      : null,
    description: safeText(alert?.rule?.description),
  };
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  if (!Array.isArray(fixture.alerts)) {
    throw new Error('Wazuh 경보 배열이 없습니다.');
  }

  return fixture.alerts.map(extractAlert);
}

// 직접 실행할 때만 출력합니다. decide.mjs에서는 사용하지 않습니다.
if (process.argv[1] &&
    fileURLToPath(import.meta.url) ===
      fileURLToPath(new URL(`file://${process.argv[1].replace(/\\/g, '/')}`))) {
  const alerts = await readAlerts();

  for (const alert of alerts) {
    console.log(JSON.stringify(alert));
  }
}
