
import { appendFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { decide } from './decide.mjs';

const XDR_DIR = dirname(fileURLToPath(import.meta.url));
const LOG_PATH = join(XDR_DIR, '..', 'alerts.log');
const TTL_MS = 15 * 60 * 1000;

// ZTNA 연동 전 단계: 별도로 관리하는 임시 거부 규칙
const denyRules = new Map();

const validIp = value =>
  typeof value === 'string' &&
  /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) &&
  value.split('.').every(part => Number(part) <= 255);

const safeId = value =>
  typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value)
    ? value
    : 'unknown';

export async function respond(alert, now = Date.now()) {
  const result = decide(alert);
  const alertId = safeId(alert?.id);

  // 만료된 규칙 제거
  for (const [ip, rule] of denyRules) {
    if (rule.expiresAtMs <= now) denyRules.delete(ip);
  }

  if (result.action === 'block' &&
      result.confidence >= 0.85 &&
      validIp(alert?.data?.srcip) &&
      alertId !== 'unknown') {
    const ip = alert.data.srcip;

    denyRules.set(ip, {
      ruleId: 'xdr.brute_force.temporary_deny',
      expiresAtMs: now + TTL_MS,
      expiresAt: new Date(now + TTL_MS).toISOString(),
      evidenceAlertId: alertId,
      reason: result.reason,
    });
  }

  // 경보 본문, 계정, 비밀번호, 토큰은 로그에 기록하지 않습니다.
  const log = JSON.stringify({
    at: new Date(now).toISOString(),
    alertId,
    action: result.action,
    confidence: result.confidence,
    reason: result.reason,
  });

  await appendFile(LOG_PATH, log + '\n', 'utf8');
  return result;
}

// 임시 차단 후보 조회: 기존 ZTNA 판정 규칙은 수정하지 않습니다.
export function checkTemporaryDeny(ip, now = Date.now()) {
  const rule = denyRules.get(ip);
  if (!rule || rule.expiresAtMs <= now) {
    if (rule) denyRules.delete(ip);
    return null;
  }
  return { ...rule };
}

// 별도 실행: 학습용 Wazuh 경보 재생
export async function replayFixture() {
  const path = join(XDR_DIR, '..', 'fixtures', 'brute-force.json');
  const fixture = JSON.parse(await readFile(path, 'utf8'));

  if (!Array.isArray(fixture.alerts)) {
    throw new Error('경보 배열이 없습니다.');
  }

  const counts = { block: 0, alert: 0, record: 0 };

  for (const alert of fixture.alerts) {
    const result = await respond(alert);
    counts[result.action]++;
  }

  return counts;
}
