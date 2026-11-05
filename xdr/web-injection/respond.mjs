
import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { decide } from './decide.mjs';

const XDR_DIR = dirname(fileURLToPath(import.meta.url));
const LOG_PATH = join(XDR_DIR, '..', 'alerts.log');
const TTL_MS = 15 * 60 * 1000;

// 학습용 ZTNA 거부 규칙 저장소
const denyRules = new Map();

const validIp = value =>
  typeof value === 'string' &&
  /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) &&
  value.split('.').every(part => Number(part) <= 255);

const safeId = value =>
  typeof value === 'string' &&
  /^[A-Za-z0-9_-]{1,80}$/.test(value)
    ? value
    : 'unknown';

export async function respond(alert, now = Date.now()) {
  const result = decide(alert);
  const alertId = safeId(alert?.id);

  // 만료된 차단 규칙 제거
  for (const [ip, rule] of denyRules) {
    if (rule.expiresAtMs <= now) {
      denyRules.delete(ip);
    }
  }

  // 명확한 공격만 임시 차단 후보에 등록
  if (
    result.action === 'block' &&
    result.confidence >= 0.85 &&
    validIp(alert?.data?.srcip) &&
    alertId !== 'unknown'
  ) {
    const ip = alert.data.srcip;

    denyRules.set(ip, {
      ruleId: 'xdr.web_injection.temporary_deny',
      expiresAtMs: now + TTL_MS,
      expiresAt: new Date(now + TTL_MS).toISOString(),
      evidenceAlertId: alertId,
      reason: result.reason,
    });
  }

  // 요청 원문, 계정, 비밀번호, 토큰은 기록하지 않습니다.
  const log = JSON.stringify({
    at: new Date(now).toISOString(),
    moduleKey: 'web-injection',
    alertId,
    action: result.action,
    confidence: result.confidence,
    reason: result.reason,
  });

  await appendFile(LOG_PATH, log + '\n', 'utf8');

  return result;
}

// 학습용 ZTNA 연결 모듈에서 임시 차단 규칙을 조회합니다.
export function checkTemporaryDeny(ip, now = Date.now()) {
  const rule = denyRules.get(ip);

  if (!rule || rule.expiresAtMs <= now) {
    if (rule) denyRules.delete(ip);
    return null;
  }

  return { ...rule };
}
