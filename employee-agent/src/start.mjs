import {createEmployeeServer} from './server.mjs';
const port=Number(process.env.PORT ?? 5189);
if (!Number.isInteger(port)||port<1024||port>65535) throw Error('Invalid local port');
const server=createEmployeeServer();
server.listen(port,'127.0.0.1',()=>console.log('신석기 직원용 PC 상태: http://127.0.0.1:'+port));
