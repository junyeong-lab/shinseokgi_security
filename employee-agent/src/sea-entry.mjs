// 직원용 SEA 진입점. 권한 상승, 집행, 외부 전송 없이 PC 상태만 제공합니다.
import {getAsset} from 'node:sea';
import {spawn} from 'node:child_process';
import {createEmployeeServer} from './server.mjs';
import {readPcStatus} from './pc-status.mjs';
const port=5189;
const pageSet=new Set(['index.html','app.js','style.css']);
const server=createEmployeeServer({
  readPc:({signal})=>readPcStatus({signal}),
  readPage:async name=>{
    if(!pageSet.has(name))throw Error('ASSET_REJECTED');
    return Buffer.from(getAsset(name));
  },
});
server.once('error',error=>{
  console.error('직원용 앱 실행 실패:',error?.code==='EADDRINUSE'?'5189 포트를 다른 프로그램이 사용 중입니다.': '로컬 서버 시작 실패');
  process.exitCode=1;
});
server.listen(port,'127.0.0.1',()=>{
  const url='http://127.0.0.1:'+port+'/';
  console.log('신석기 직원용 PC 보안 앱: '+url);
  if(process.platform==='win32'){
    try{
      const child=spawn('explorer.exe',[url],{detached:true,stdio:'ignore',windowsHide:true});
      child.on('error',()=>console.log('브라우저에서 직접 주소를 열어주세요.'));
      child.unref();
    }catch{console.log('브라우저에서 직접 주소를 열어주세요.');}
  }
});
