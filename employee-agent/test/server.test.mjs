import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createEmployeeServer} from '../src/server.mjs';
test('직원용 앱은 로컬 상태를 읽기 전용으로 제공하고 관리자 API를 열지 않는다',async()=>{
  const measuredAt=new Date().toISOString();
  const server=createEmployeeServer({readPc:async()=>({source:'local-pc',measuredAt,metrics:{network:{state:'ok',interfaceCount:1,ipv4Count:1}}})});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url='http://127.0.0.1:'+server.address().port;
  try{
    const home=await fetch(url);assert.equal(home.status,200);assert.match(await home.text(),/내 PC 상태/);
    const api=await fetch(url+'/api/pc/status');assert.equal(api.status,200);
    const data=await api.json();assert.equal(data.ok,true);assert.equal(data.data.source,'local-pc');assert.equal(data.data.metrics.network.interfaceCount,1);
    assert.equal((await fetch(url+'/admin')).status,404);
    assert.equal((await fetch(url+'/api/pc/status',{method:'POST'})).status,405);
    assert.equal((await fetch(url+'/api/pc/status',{headers:{host:'example.com'}})).status,403);
  }finally{await new Promise((resolve,reject)=>server.close(err=>err?reject(err):resolve()));}
});
