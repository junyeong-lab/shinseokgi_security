import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { decide as brute } from '../xdr/brute-force/decide.mjs';
import { decide as web } from '../xdr/web-injection/decide.mjs';
import { decide as cve } from '../xdr/known-cve/decide.mjs';
import { decide as persistence } from '../xdr/persistence/decide.mjs';
import { decide as privilege } from '../xdr/privilege/decide.mjs';
import { decide as exfiltration } from '../xdr/exfiltration/decide.mjs';

const handlers = {
  'brute-force': brute,
  'web-injection': web,
  'known-cve': cve,
  'persistence': persistence,
  'privilege': privilege,
  'exfiltration': exfiltration
};

function chooseModule(alert) {
  const ids = Array.isArray(alert.rule?.mitre)
    ? alert.rule.mitre.filter(x => typeof x === 'string')
    : [];

  const has = id => ids.some(x => x === id || x.startsWith(id + '.'));
  const description = String(alert.rule?.description || '');

  if (has('T1110')) return 'brute-force';
  if (has('T1190') && /CVE-2021-44228|Log4Shell/i.test(description))
    return 'known-cve';
  if (has('T1190')) return 'web-injection';
  if (has('T1543') || has('T1053')) return 'persistence';
  if (has('T1041') || has('T1048')) return 'exfiltration';
  if (has('T1068') || has('T1078') || has('T1548'))
    return 'privilege';

  return null;
}

export function analyzeBatch(batch) {
  if (
    batch?.schema !== 'shinseokgi.wazuh.alerts.v1' ||
    !Array.isArray(batch.alerts) ||
    batch.alerts.length !== batch.count ||
    batch.alerts.length > 100
  ) {
    throw new Error('Invalid Wazuh batch');
  }

  const results = batch.alerts.map(alert => {
    if (
      alert?.source !== 'wazuh' ||
      !alert.rule?.id ||
      !alert.agent?.name
    ) {
      throw new Error('Invalid Wazuh alert');
    }

    const module = chooseModule(alert);
    const decision = module
      ? handlers[module](alert)
      : {
          action: 'not-assessed',
          confidence: null,
          reason: '지원하는 XDR 분석 모듈과 명확한 대응 관계 없음'
        };

    return {
      id: alert.id,
      timestamp: alert.timestamp,
      agent: alert.agent.name,
      ruleId: alert.rule.id,
      level: alert.rule.level,
      description: alert.rule.description,
      mitre: alert.rule.mitre,
      module,
      action: decision.action,
      confidence: decision.confidence,
      reason: decision.reason
    };
  });

  return {
    schema: 'shinseokgi.xdr.batch.v1',
    mode: 'on-demand-ssh',
    total: results.length,
    routed: results.filter(x => x.module !== null).length,
    notAssessed: results.filter(x => x.module === null).length,
    results
  };
}

async function main() {
  process.stdin.setEncoding('utf8');
  let input = '';

  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 1000000) {
      throw new Error('Input too large');
    }
  }

  const result = analyzeBatch(JSON.parse(input));

  console.log('BATCH_XDR_ANALYSIS_OK');
  console.log('Total:', result.total);
  console.log('Routed:', result.routed);
  console.log('Not assessed:', result.notAssessed);

  for (const item of result.results.slice(0, 5)) {
    console.log(
      'Rule:', item.ruleId,
      '| Module:', item.module || 'none',
      '| Action:', item.action
    );
  }
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
