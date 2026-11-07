const byId=id=>document.getElementById(id);
const refresh=byId('refresh'),status=byId('status');
const metricKeys=['cpu','memory','disk','network','firewall','events'];
const gb=n=>Number.isFinite(n)&&n>=0?(n/1073741824).toFixed(1)+' GB':null;
const count=n=>Number.isSafeInteger(n)&&n>=0;
function format(key,metric){
  if(metric?.state!=='ok')return ['확인 불가','조회할 수 없는 항목입니다.'];
  switch(key){
    case 'cpu':return Number.isFinite(metric.usagePercent)&&metric.usagePercent>=0&&metric.usagePercent<=100?[metric.usagePercent.toFixed(1)+'%','현재 사용률(짧은 구간 측정)']:['확인 불가','측정값을 확인할 수 없습니다.'];
    case 'memory':{const used=gb(metric.usedBytes),total=gb(metric.totalBytes);return used&&total&&metric.usedBytes<=metric.totalBytes?[used+' / '+total,'사용 중 / 전체']:['확인 불가','측정값을 확인할 수 없습니다.'];}
    case 'disk':{const free=gb(metric.freeBytes),total=gb(metric.totalBytes);return free&&total&&metric.freeBytes<=metric.totalBytes?[free,'전체 '+total]:['확인 불가','측정값을 확인할 수 없습니다.'];}
    case 'network':return count(metric.interfaceCount)&&count(metric.ipv4Count)?[metric.interfaceCount+'개 인터페이스','IPv4 구성 '+metric.ipv4Count+'개 (인터넷 연결 판정 아님)']:['확인 불가','측정값을 확인할 수 없습니다.'];
    case 'firewall':{
      const names=['Domain','Private','Public'],profiles=metric.profiles;
      if(!Array.isArray(profiles)||profiles.length!==3||!names.every(name=>profiles.filter(p=>p?.name===name&&typeof p.enabled==='boolean').length===1))return ['확인 불가','설정을 확인할 수 없습니다.'];
      const active=profiles.filter(p=>p.enabled).length;return [active+' / 3개 켜짐',names.map(name=>name+': '+(profiles.find(p=>p.name===name).enabled?'켜짐':'꺼짐')).join(' · ')];}
    case 'events':return count(metric.warningCount)&&count(metric.errorCount)&&metric.sampleLimit===5000&&typeof metric.truncated==='boolean'?[metric.errorCount+'건 오류','최근 24시간 경고 '+metric.warningCount+'건'+(metric.truncated?' · 일부 집계':'')+' (침해 판정 아님)']:['확인 불가','이벤트를 읽을 수 없습니다.'];
  }
  return ['확인 불가','알 수 없는 항목입니다.'];
}
let busy=false;
function reset(){
  for(const key of metricKeys){byId(key).textContent='확인 불가';byId(key+'Note').textContent='최신 상태를 확인하지 못했습니다.';}
}
async function load(){
  if(busy)return;busy=true;refresh.disabled=true;status.textContent='PC 상태를 확인하는 중입니다.';
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),10000);
  try{
    const response=await fetch('/api/pc/status',{cache:'no-store',signal:controller.signal});
    if(!response.ok)throw Error('REQUEST_FAILED');
    const body=await response.json(),data=body?.data,at=Date.parse(data?.measuredAt);
    if(body?.ok!==true||data?.schema!=='shinseokgi.pc-status.v1'||data?.source!=='local-pc'||!Number.isFinite(at)||Math.abs(Date.now()-at)>60000)throw Error('INVALID_DATA');
    for(const key of metricKeys){const [value,note]=format(key,data.metrics?.[key]);byId(key).textContent=value;byId(key+'Note').textContent=note;}
    status.textContent='마지막 확인: '+new Date(at).toLocaleString('ko-KR')+' · 이 PC의 실측값';
  }catch{reset();status.textContent='이번 PC 상태 조회에 실패했습니다. 잠시 후 다시 확인해 주세요.';}
  finally{clearTimeout(timer);busy=false;refresh.disabled=false;}
}
refresh.addEventListener('click',load);void load();
