import { spawn } from 'node:child_process';
import { decide } from '../xdr/brute-force/decide.mjs';

async function main() {
  const output = await new Promise((resolve, reject) => {
    const ssh = spawn('ssh', [
      'potato@10.10.247.10',
      'sudo -n /usr/bin/python3 /usr/local/libexec/shinseokgi-xdr/export-rule100777.py'
    ], { stdio: ['inherit', 'pipe', 'inherit'] });

    let data = '';

    ssh.stdout.setEncoding('utf8');
    ssh.stdout.on('data', chunk => {
      data += chunk;
      if (data.length > 65536) {
        ssh.kill();
        reject(new Error('경보 응답 크기 초과'));
      }
    });

    ssh.on('error', reject);
    ssh.on('close', code => {
      if (code === 0) resolve(data);
      else reject(new Error('SSH 경보 수집 실패'));
    });
  });

  const alert = JSON.parse(output);

  if (
    alert.source !== 'wazuh' ||
    String(alert.agent?.id) !== '002' ||
    String(alert.rule?.id) !== '100777' ||
    String(alert.data?.eventID) !== '777'
  ) {
    throw new Error('예상한 Wazuh 테스트 경보가 아닙니다.');
  }

  const result = await decide(alert);

  console.log(JSON.stringify({
    source: 'wazuh',
    mode: 'on-demand-ssh',
    agent: alert.agent.name,
    ruleId: alert.rule.id,
    module: 'brute-force',
    ...result
  }, null, 2));
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
