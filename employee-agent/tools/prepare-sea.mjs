// Node.js 24 SEA 준비물 생성. 이 파일은 Windows x64 개발 PC에서만 실행합니다.
import {build} from 'esbuild';
import {mkdir,copyFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname,join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const dist=join(root,'dist');
if(process.platform!=='win32'||process.arch!=='x64')throw Error('Windows x64에서만 빌드하세요.');
if(!/^v24\./.test(process.version))throw Error('Node.js 24 버전에서 빌드하세요.');
await mkdir(dist,{recursive:true});
const bundle=join(dist,'sea-main.cjs');
const exe=join(dist,'ShinseokgiEmployeeAgent.exe');
await build({entryPoints:[join(root,'src','sea-entry.mjs')],outfile:bundle,bundle:true,platform:'node',format:'cjs',target:'node24',logLevel:'warning'});
const config={
  main:bundle,output:join(dist,'sea-prep.blob'),disableExperimentalSEAWarning:true,useSnapshot:false,useCodeCache:false,
  assets:{
    'index.html':join(root,'public','index.html'),
    'app.js':join(root,'public','app.js'),
    'style.css':join(root,'public','style.css'),
  }
};
const configPath=join(dist,'sea-config.json');
await writeFile(configPath,JSON.stringify(config,null,2)+'\n');
await exec(process.execPath,['--experimental-sea-config',configPath],{cwd:root,windowsHide:true});
await copyFile(process.execPath,exe);
console.log('SEA 바이너리 복사 완료:',exe);
console.log('이후 npm 스크립트에서 postject로 프로그램이 삽입됩니다.');
