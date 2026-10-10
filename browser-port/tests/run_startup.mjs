import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const build=path.join(root,'build');
const manifest=JSON.parse(await fs.readFile(path.join(build,'startup.json'),'utf8'));
const create=(await import(pathToFileURL(path.join(build,manifest.module)))).default;
const wasmBytes=await fs.readFile(path.join(build,'startup.wasm'));
if(createHash('sha256').update(wasmBytes).digest('hex')!==manifest.artifact_sha256['startup.wasm'])throw Error('Startup Wasm identity mismatch');
const m=await create({wasmBinary:wasmBytes});
const c=manifest.case;
m._reset();
if(m._configure_platform)m._configure_platform(manifest.image.address);
else if(m._win32_reset)m._win32_reset(manifest.image.address);
for(const r of c.regions)if(m._map_region(r.address,r.size,r.permissions)!==1)throw Error('Invalid PE map region');
const memory=m.HEAPU8.subarray(m._memory_base(),m._memory_base()+m._memory_size());
const imageBytes=await fs.readFile(path.join(build,manifest.image.url));
if(createHash('sha256').update(imageBytes).digest('hex')!==manifest.image.sha256)throw Error('Startup image identity mismatch');
memory.set(imageBytes,manifest.image.address);
for(const w of c.writes)memory.set(w.bytes,w.address);
c.registers.forEach((v,i)=>m._set_reg(i,v));m._set_flags(c.eflags);m._set_eip(c.entry);m._set_fs_base(c.fsBase);
const started=performance.now();
const status=m._run(c.maxSteps,c.stop);
const state={captured_at_utc:new Date().toISOString(),status,steps:m._get_steps(),elapsed_ms:performance.now()-started,
  eip:m._get_eip()>>>0,registers:Array.from({length:8},(_,i)=>m._get_reg(i)>>>0),eflags:m._get_flags()>>>0,
  fault:{code:m._fault_code(),address:m._fault_address()>>>0,message:m.UTF8ToString(m._fault_text())},
  trace:Array.from({length:m._get_trace_count()},(_,i)=>m._get_trace(i)>>>0),
  wasm_memory_bytes:m.HEAPU8.byteLength,gameplay_demonstrated:false,manifest};
const stack=state.registers[4];
state.stack_words=stack+48<=memory.byteLength?Array.from({length:12},(_,i)=>new DataView(memory.buffer,memory.byteOffset+stack+i*4,4).getUint32(0,true)):[];
state.reproduction={build:`.\\.venv\\Scripts\\python.exe -m tools.build_startup --limit ${manifest.provenance.instruction_limit} ${(manifest.provenance.seeds||[]).map(a=>'--seed 0x'+a.toString(16)).join(' ')}`,
  run:'.\\.tools\\emsdk-4.0.23\\node\\22.16.0_64bit\\bin\\node.exe tests/run_startup.mjs'};
await fs.writeFile(path.join(root,'artifacts/startup-node.json'),JSON.stringify(state,null,2)+'\n');
await fs.appendFile(path.join(root,'artifacts/startup-history.jsonl'),JSON.stringify(state)+'\n');
console.log(JSON.stringify({status,steps:state.steps,elapsed_ms:state.elapsed_ms,eip:'0x'+state.eip.toString(16),fault:state.fault,
  trace_tail:state.trace.slice(-8).map(v=>'0x'+v.toString(16)),wasm_memory_bytes:state.wasm_memory_bytes,gameplay_demonstrated:false},null,2));
// Reaching a compatibility barrier is evidence, not an exit-code success claim.
if(status!==1)process.exitCode=2;
