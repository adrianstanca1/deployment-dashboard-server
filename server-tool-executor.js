/**
 * AI Tool Executor
 */
const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const os = require('os');

const execAsync = util.promisify(exec);

function formatBytes(b) { if (!b) return '0'; const k = 1024, s = ['B','KB','MB','GB']; const i = Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]; }
function safePath(p) { const r = path.resolve(p); if (r.startsWith('/proc')||r.startsWith('/sys')||r.startsWith('/dev')) throw new Error('Access denied'); return r; }

async function pm2_list() { try { const { stdout } = await execAsync('pm2 jlist'); return { success: true, processes: JSON.parse(stdout).map(p => ({ name: p.name, status: p.pm2_env?.status, cpu: p.monit?.cpu, memory: p.monit?.memory }))}; } catch(e) { return { success: false, error: e.message }; }}
async function pm2_restart({ processName }) { try { await execAsync(`pm2 restart ${processName}`); return { success: true, output: `Restarted ${processName}`}; } catch(e) { return { success: false, error: e.message }; }}
async function pm2_stop({ processName }) { try { await execAsync(`pm2 stop ${processName}`); return { success: true, output: `Stopped ${processName}`}; } catch(e) { return { success: false, error: e.message }; }}
async function pm2_logs({ processName, lines=50 }) { try { const { stdout } = await execAsync(`pm2 logs ${processName} --lines ${lines} --nostream`); return { success: true, logs: stdout.slice(-5000)}; } catch(e) { return { success: false, error: e.message }; }}
async function deploy_app({ repo, port, name }) { const dir = `/root/deployed/${name}`; try { if(fs.existsSync(dir)) await execAsync(`rm -rf ${dir}`); await execAsync(`git clone https://github.com/${repo}.git ${dir}`); if(fs.existsSync(path.join(dir,'package.json'))) await execAsync('npm install',{cwd:dir}); await execAsync(`pm2 start npm --name "${name}" -- start`,{cwd:dir,env:{...processport?.toString()}}); return { success.env,PORT:: true, output: `Deployed ${name} on port ${port}`}; } catch(e) { return { success:false, error:e.message }; }}

async function db_list() { const dbs=[]; try{await execAsync('which mysql');dbs.push({type:'mysql'})}catch{} try{await execAsync('which psql');dbs.push({type:'postgres'})}catch{} return{success:true,databases:dbs.length?dbs:[{type:'none'}]};}
async function db_query({ database, query }) { if(!query.trim().toUpperCase().startsWith('SELECT')) return{success:false,error:'SELECT only'}; try{let r; if(database==='mysql')({stdout:r}=await execAsync(`mysql -e "${query}"`)); else if(database==='postgres')({stdout:r}=await execAsync(`psql -c "${query}"`)); return{success:true,output:r};}catch(e){return{success:false,error:e.message};}}
async function db_backup({ database, databaseType }) { const bd='/root/backups',ts=new Date().toISOString().replace(/[:.]/g,'-'),fp=path.join(bd,`${database}_${ts}.sql`); try{if(!fs.existsSync(bd))fs.mkdirSync(bd,{recursive:true});await execAsync(databaseType==='mysql'?`mysqsqldump ${database} > ${fp}`:`pg_dump ${database} > ${fp}`);return{success:true,output:`Backup: ${fp}`};}catch(e){return{success:false,error:e.message};}}

async function git_status({ path: p='/root' }) { try{const s=safePath(p),{stdout}=await execAsync('git status --porcelain',{cwd:s}),{stdout:b}=await execAsync('git branch --show-current',{cwd:s}),files=stdout.trim().split('\n').filter(Boolean).map(l=>({status:l.slice(0,2),file:l.slice(3)}));return{success:true,branch:b.trim(),files,isClean:!files.length};}catch(e){return{success:false,error:e.message};}}
async function git_pull({ path:p, branch='main' }) { try{await execAsync(`git pull origin ${branch}`,{cwd:safePath(p)});return{success:true,output:'Pulled'};}catch(e){return{success:false,error:e.message};}}
async function git_commit({ path:p, message, addAll=true }) { try{const s=safePath(p);if(addAll)await execAsync('git add -A',{cwd:s});await execAsync(`git commit -m "${message}"`,{cwd:s});return{success:true,output:'Committed'};}catch(e){return{success:false,error:e.message};}}
async function git_branch_list({ path:p='/root' }) { try{const {stdout}=await execAsync('git branch -a',{cwd:safePath(p)});return{success:true,branches:stdout.trim().split('\n').map(b=>({name:b.replace(/^\*|\s+/g,''),current:b.includes('*')}))};}catch(e){return{success:false,error:e.message};}}
async function github_create_pr({ owner, repo, title, body, head, base='main' }) { const t=process.env.GITHUB_TOKEN; if(!t)return{success:false,error:'No token'}; try{const r=await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls`,{method:'POST',headers:{'Authorization':`Bearer ${t}`,'Content-Type':'application/json'},body:JSON.stringify({title,body,head,base})});if(!r.ok)return{success:false,error:(await r.json()).message};const pr=await r.json();return{success:true,output:`PR: ${pr.html_url}`,url:pr.html_url};}catch(e){return{success:false,error:e.message};}}

async function system_stats() { const c=os.cpus();let ti=0,ti2=0;c.forEach(cpu=>{for(let t in cpu.times)ti+=cpu.times[t];ti2+=cpu.times.idle});const cpu=100-100*ti2/ti;let du={total:0,free:0,used:0};try{const{stdout}=await execAsync('df -k / | tail -1');const p=stdout.trim().split(/\s+/);du={total:parseInt(p[1])*1024,free:parseInt(p[3])*1024,used:parseInt(p[2])*1024};}catch{} return{success:true,cpu:{usage:cpu.toFixed(1),cores:c.length},memory:{total:formatBytes(os.totalmem()),free:formatBytes(os.freemem()),pct:((os.totalmem()-os.freemem())/os.totalmem()*100).toFixed(1)},disk:{total:formatBytes(du.total),free:formatBytes(du.free),used:formatBytes(du.used)},uptime:os.uptime()};}
async function docker_stats({ all=false }) { try{const{stdout}=await execAsync(`docker stats --no-stream --format "{{.Container}}|{{.CPUPerc}}|{{.MemUsage}}|{{.Status}}" ${all?'-a':''}`);return{success:true,containers:stdout.trim().split('\n').filter(Boolean).map(l=>{const[c,cpu,m,s]=l.split('|');return{container:c,cpu,memory:m,status:s}})};}catch(e){return{success:false,error:e.message};}}
async function docker_list({ all=false }) { try{const{stdout}=await execAsync(`docker ps ${all?'-a':''} --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}"`);return{success:true,containers:stdout.trim().split('\n').filter(Boolean).map(l=>{const[id,n,i,s]=l.split('|');return{id,name:n,image:i,status:s}})};}catch(e){return{success:false,error:e.message};}}
async function check_url({ url, expectedStatus=200, timeout=10 }) { try{const c=new AbortController(),id=setTimeout(()=>c.abort(),timeout*1000);const r=await fetch(url,{signal:c.signal});clearTimeout(id);return{success:r.status===expectedStatus,url,status:r.status,expected:expectedStatus};}catch(e){return{success:false,url,error:e.message};}}
async function send_alert({ message, severity='info', service }) { const a=`[${new Date().toISOString()}] [${severity.toUpperCase()}]${service?` [${service}]`:''} ${message}`;severity==='critical'?console.error('🚨',a):severity==='warning'?console.warn('⚠️',a):console.log('ℹ️',a);return{success:true,alert:a};}

async function file_read({ path:p, lines=100 }) { try{const c=fs.readFileSync(safePath(p),'utf8'),l=c.split('\n');return{success:true,path:p,totalLines:l.length,content:l.slice(-lines).join('\n')};}catch(e){return{success:false,error:e.message};}}
async function file_write({ path:p, content, append=false }) { try{const s=safePath(p),d=path.dirname(s);if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true});append?fs.appendFileSync(s,content,'utf8'):fs.writeFileSync(s,content,'utf8');return{success:true,path:s,size:formatBytes(fs.statSync(s).size)};}catch(e){return{success:false,error:e.message};}}
async function file_search({ pattern, path:p='/root', fileType, maxResults=50 }) { try{const cmd=fileType?`find "${p}" -name "*.${fileType}" -exec grep -l "${pattern}" {} \\;`:`grep -rl "${pattern}" "${p}"`;const{stdout}=await execAsync(cmd,{maxBuffer:10*1024*1024});const files=stdout.trim().split('\n').filter(Boolean).slice(0,maxResults);return{success:true,pattern,path:p,files,count:files.length};}catch(e){return{success:false,error:e.message};}}
async function file_list({ path:p='.', pattern }) { try{const{stdout}=await execAsync(`ls "${p}"`);let files=stdout.trim().split('\n').filter(Boolean);if(pattern){const r=new RegExp(pattern.replace(/\*/g,'.*').replace(/\?/g,'.'));files=files.filter(f=>r.test(f));}return{success:true,path:p,files,count:files.length};}catch(e){return{success:false,error:e.message};}}
async function file_exists({ path:p }) { try{const s=fs.statSync(safePath(p));return{success:true,exists:true,isFile:s.isFile(),isDirectory:s.isDirectory(),size:formatBytes(s.size)};}catch(e){return e.code==='ENOENT'?{success:true,exists:false}:{success:false,error:e.message};}}
async function file_get_info({ path:p }) { try{const s=fs.statSync(safePath(p));return{success:true,path:p,size:formatBytes(s.size),isFile:s.isFile(),isDirectory:s.isDirectory(),modified:s.mtime};}catch(e){return{success:false,error:e.message};}}

const TOOL_EXECUTORS = { pm2_list, pm2_restart, pm2_stop, pm2_logs, deploy_app, db_list, db_query, db_backup, git_status, git_pull, git_commit, git_branch_list, github_create_pr, system_stats, docker_stats, docker_list, check_url, send_alert, file_read, file_write, file_search, file_list, file_exists, file_get_info };

async function executeTool(name, params) {
  const fn = TOOL_EXECUTORS[name];
  if (!fn) return { success: false, error: `Unknown: ${name}` };
  try { return await fn(params || {}); } catch (e) { return { success: false, error: e.message, tool: name }; }
}

module.exports = { executeTool, TOOL_EXECUTORS };
