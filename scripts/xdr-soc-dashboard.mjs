import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { analyzeBatch } from './xdr-wazuh-analyze.mjs';

const HOST = '127.0.0.1';
const PORT = 5190;
let snapshot = null;
let fetchedAt = null;
let fetching = false;

const HTML = String.raw`<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>신석기백화점 | XDR SOC</title>
<style>
:root{color-scheme:dark;font:14px/1.5 system-ui,'Malgun Gothic',sans-serif;background:#0c1421;color:#e7eef9}
*{box-sizing:border-box}body{margin:0}header{background:#121f30;border-bottom:1px solid #293a51;padding:18px max(24px,calc((100vw - 1400px)/2))}
h1{font-size:20px;margin:0}header p{color:#9db0ca;margin:3px 0 0}.wrap{max-width:1400px;margin:auto;padding:24px}
.top{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap}.note{color:#a8b9d0}
button{border:0;background:#3987ff;color:white;padding:11px 17px;border-radius:9px;cursor:pointer;font:inherit;font-weight:700}button:disabled{opacity:.6;cursor:wait}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}.stat{border:1px solid #293a51;border-radius:12px;background:#152338;padding:17px}.stat .value{font-size:28px;font-weight:750}.stat .label{color:#a7b9d2}
.panel{background:#121f30;border:1px solid #293a51;border-radius:12px;padding:16px;margin-top:14px}
.filters{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}input,select{background:#0c1828;border:1px solid #354963;border-radius:8px;color:#e7eef9;padding:9px 11px;font:inherit}input{flex:1;min-width:200px}
.layout{display:grid;grid-template-columns:minmax(0,2fr) minmax(270px,1fr);gap:14px}.scroll{overflow:auto;max-height:65vh}
table{width:100%;border-collapse:collapse;text-align:left;white-space:nowrap}th,td{padding:11px 10px;border-bottom:1px solid #29374b}th{position:sticky;top:0;background:#16273b;color:#afc5e3;font-weight:600}tbody tr{cursor:pointer}tbody tr:hover,tbody tr.selected{background:#21344d}
.tag{padding:3px 7px;border-radius:6px;background:#273b53;display:inline-block;font-size:12px}.record{color:#a7e0c5}.alert{color:#ffdd8c}.block{color:#ffaaa9}.muted{color:#a6b4c8}
dl{margin:0}dt{margin:12px 0 3px;color:#8fa5c3}dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}h2{font-size:16px;margin:0 0 8px}.foot{font-size:12px;color:#9db0ca;margin-top:14px}
@media(max-width:900px){.layout{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.wrap{padding:14px}}
</style>
</head>
<body>
<header><h1>신석기백화점 · XDR SOC</h1><p>Wazuh 실측 경보 / 요청형 SSH 수집 / 읽기 전용 분석</p></header>
<main class="wrap">
<div class="top"><div><strong id="status">아직 수집하지 않았습니다.</strong><div class="note" id="updated">새로고침 시 PowerShell 창에서 SSH 비밀번호를 입력하세요.</div></div><button id="refresh">Wazuh 경보 가져오기</button></div>
<section class="stats"><div class="stat"><div class="label">최근 조회 경보</div><div class="value" id="total">—</div></div><div class="stat"><div class="label">XDR 모듈 연결</div><div class="value" id="routed">—</div></div><div class="stat"><div class="label">분석 미대상</div><div class="value" id="unknown">—</div></div><div class="stat"><div class="label">추가 검토 후보</div><div class="value" id="review">—</div></div></section>
<div class="filters"><input id="search" placeholder="Rule · 장비 · 설명 검색"><select id="agent"><option value="">전체 장비</option></select><select id="module"><option value="">전체 분석 모듈</option></select><select id="action"><option value="">전체 판정</option><option value="not-assessed">분석 미대상</option><option value="record">기록</option><option value="alert">추가 검토</option><option value="block">차단 검토(미실행)</option></select></div>
<div class="layout"><section class="panel"><h2>경보 목록 <span class="note" id="shown"></span></h2><div class="scroll"><table><thead><tr><th>발생 시각</th><th>장비</th><th>Rule</th><th>Wazuh Level</th><th>XDR 모듈</th><th>판정</th></tr></thead><tbody id="rows"></tbody></table></div></section><aside class="panel"><h2>경보 상세</h2><div id="detail" class="note">목록에서 경보를 선택하세요.</div></aside></div>
<p class="foot">주의: action=block은 분석기의 제안일 뿐 실제 차단이 아닙니다. 신뢰값은 보안성·악성 확률의 보증이 아닙니다. 이 화면은 수동 요청 시점의 스냅샷이며 상시 실시간 수집이 아닙니다.</p>
</main>
<script>
'use strict';
const byId=id=>document.getElementById(id);
let batch=null;
let selected=null;
const actions={'not-assessed':'분석 미대상','record':'기록','alert':'추가 검토','block':'차단 검토(미실행)'};
const modules={'brute-force':'로그인 추측','web-injection':'웹 주입','known-cve':'알려진 CVE','persistence':'지속성','privilege':'권한·계정','exfiltration':'정보 반출'};
function addInfo(parent,name,value){const dt=document.createElement('dt');dt.textContent=name;const dd=document.createElement('dd');dd.textContent=value??'—';parent.append(dt,dd)}
function showDetail(item){selected=item?.id??null;const area=byId('detail');area.replaceChildren();if(!item){area.textContent='목록에서 경보를 선택하세요.';return}const dl=document.createElement('dl');addInfo(dl,'경보 ID',item.id);addInfo(dl,'발생 시각',item.timestamp);addInfo(dl,'장비',item.agent);addInfo(dl,'Wazuh 규칙 / Level',item.ruleId+' / '+item.level);addInfo(dl,'MITRE ATT&CK',Array.isArray(item.mitre)?(item.mitre.join(', ')||'없음'):'없음');addInfo(dl,'XDR 모듈',modules[item.module]||'분석 미대상');addInfo(dl,'XDR 판정',actions[item.action]||item.action);addInfo(dl,'판정 신뢰값',item.confidence===null?'판정 없음':String(item.confidence));addInfo(dl,'Wazuh 규칙 설명',item.description);addInfo(dl,'XDR 판정 근거',item.reason);area.append(dl)}
function fillSelect(id,values,labels){const el=byId(id);while(el.options.length>1)el.remove(1);for(const v of values){const opt=document.createElement('option');opt.value=v;opt.textContent=labels?.[v]||v;el.append(opt)}}
function render(){if(!batch)return;const q=byId('search').value.trim().toLocaleLowerCase();const a=byId('agent').value,m=byId('module').value,act=byId('action').value;const list=batch.results.filter(x=>(!a||x.agent===a)&&(!m||x.module===m)&&(!act||x.action===act)&&(!q||[x.ruleId,x.agent,x.description,x.reason].some(v=>String(v??'').toLocaleLowerCase().includes(q))));byId('shown').textContent='('+list.length+'건 표시)';const currentIsVisible=list.some(x=>x.id===selected);if(!currentIsVisible){showDetail(list[0]||null);if(list.length===0)byId('detail').textContent='현재 검색·필터 조건에 맞는 경보가 없습니다.'}const body=byId('rows');body.replaceChildren();for(const item of list){const tr=document.createElement('tr');if(item.id===selected)tr.classList.add('selected');for(const val of [item.timestamp,item.agent,item.ruleId,item.level,modules[item.module]||'미대상',actions[item.action]||item.action]){const td=document.createElement('td');td.textContent=String(val??'—');tr.append(td)}tr.addEventListener('click',()=>{showDetail(item);render()});body.append(tr)}}
function accept(state){if(!state?.data)return;batch=state.data;byId('total').textContent=batch.total;byId('routed').textContent=batch.routed;byId('unknown').textContent=batch.notAssessed;byId('review').textContent=batch.results.filter(x=>x.action==='alert'||x.action==='block').length;byId('updated').textContent='마지막 수동 조회: '+(state.fetchedAt||'확인 안 됨');fillSelect('agent',[...new Set(batch.results.map(x=>x.agent))].sort());fillSelect('module',[...new Set(batch.results.map(x=>x.module).filter(Boolean))].sort(),modules);byId('status').textContent='Wazuh 경보 수집·XDR 분석 성공';showDetail(batch.results[batch.results.length-1]);render()}
async function refresh(){const button=byId('refresh');button.disabled=true;byId('status').textContent='경보 조회 중 — PowerShell에서 SSH 비밀번호를 입력하세요.';try{const response=await fetch('/api/refresh',{method:'POST',headers:{'Content-Type':'application/json'}});const data=await response.json();if(!response.ok)throw Error(data.error||'수집 실패');accept(data)}catch(error){byId('status').textContent='조회 실패: '+error.message}finally{button.disabled=false}}
byId('refresh').addEventListener('click',refresh);
for(const id of ['search','agent','module','action'])byId(id).addEventListener(id==='search'?'input':'change',render);
fetch('/api/state').then(r=>r.json()).then(accept).catch(()=>{});
</script>
</body>
</html>`;

function respond(res, code, value) {
  const content = JSON.stringify(value);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(content);
}

function collect() {
  return new Promise((resolve, reject) => {
    const ssh = spawn('ssh', [
      'potato@10.10.247.10',
      'sudo -n /usr/bin/python3 /usr/local/libexec/shinseokgi-xdr/export-recent.py'
    ], { stdio: ['inherit', 'pipe', 'inherit'] });
    let output = '';
    let failed = false;
    ssh.stdout.setEncoding('utf8');
    ssh.stdout.on('data', chunk => {
      output += chunk;
      if (output.length > 2000000) { failed = true; ssh.kill(); }
    });
    ssh.on('error', reject);
    ssh.on('close', code => {
      if (failed || code !== 0) return reject(new Error('SSH 원격 경보 추출 실패'));
      try { resolve(analyzeBatch(JSON.parse(output))); }
      catch (error) { reject(error); }
    });
  });
}

const server = createServer(async (req, res) => {
  const url = req.url?.split('?')[0];
  if (req.method === 'GET' && url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    res.end(HTML);
  } else if (req.method === 'GET' && url === '/api/state') {
    respond(res, 200, { fetchedAt, data: snapshot });
  } else if (req.method === 'POST' && url === '/api/refresh') {
    if (req.headers.origin && req.headers.origin !== 'http://127.0.0.1:5190') {
      return respond(res, 403, { error: '요청 출처를 허용하지 않습니다.' });
    }
    if (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') {
      return respond(res, 403, { error: '다른 사이트에서 요청할 수 없습니다.' });
    }
    if (fetching) return respond(res, 409, { error: '이미 조회 중입니다.' });
    fetching = true;
    try {
      console.log('Wazuh SSH 인증 요청: 필요한 경우 아래에 비밀번호를 입력하세요.');
      snapshot = await collect();
      fetchedAt = new Date().toLocaleString('ko-KR');
      console.log('XDR_SOC_REFRESH_OK:', snapshot.total);
      respond(res, 200, { fetchedAt, data: snapshot });
    } catch (error) {
      console.error('수집 실패:', error.message);
      respond(res, 502, { error: error.message });
    } finally { fetching = false; }
  } else {
    respond(res, 404, { error: 'Not found' });
  }
});
server.listen(PORT, HOST, () => {
  console.log('XDR_SOC_DASHBOARD_READY http://' + HOST + ':' + PORT);
  console.log('종료: Ctrl+C / 외부 접속 불가 / 자동 차단 없음');
});
