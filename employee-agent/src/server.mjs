import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {readPcStatus} from './pc-status.mjs';

// 직원 PC에서만 작동하는 읽기 전용 로컬 서버입니다.
// IT 관리 기능이나 원격 접속·집행 API를 노출하지 않습니다.
const pages = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
const securityHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
function send(res, status, body, type='application/json; charset=utf-8') {
  res.writeHead(status, {...securityHeaders, 'Content-Type': type});
  res.end(typeof body==='string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const localHost = value => /^(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$/i.test(value ?? '');

export function createEmployeeServer({readPc=readPcStatus,readPage=name=>readFile(join(process.cwd(),'public',name))}={}) {
  return http.createServer(async (req,res)=>{
    if (!localHost(req.headers.host)) return send(res,403,{ok:false,error:'LOCAL_ONLY'});
    if (req.method!=='GET') return send(res,405,{ok:false,error:'READ_ONLY'});
    const path=req.url?.split('?')[0];
    if (path==='/api/pc/status') {
      const controller = new AbortController();
      const timer = setTimeout(()=>controller.abort(),9000);
      try {
        const result=await readPc({signal:controller.signal});
        if (result?.source!=='local-pc' || typeof result.measuredAt!=='string' || !result.metrics || typeof result.metrics!=='object') throw Error('INVALID_STATUS');
        return send(res,200,{ok:true,data:{schema:'shinseokgi.pc-status.v1',source:'local-pc',measuredAt:result.measuredAt,metrics:result.metrics}});
      } catch {
        return send(res,503,{ok:false,error:'STATUS_UNAVAILABLE'});
      } finally { clearTimeout(timer); }
    }
    const page=pages.get(path);
    if (!page) return send(res,404,{ok:false,error:'NOT_FOUND'});
    try { return send(res,200,await readPage(page[0]),page[1]); }
    catch { return send(res,503,{ok:false,error:'PAGE_UNAVAILABLE'}); }
  });
}
