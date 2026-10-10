import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const build=path.join(root,'build');
const manifest=JSON.parse(await fs.readFile(path.join(build,'startup.json'),'utf8'));
const create=(await import(pathToFileURL(path.join(build,manifest.module)))).default;
const m=await create({wasmBinary:await fs.readFile(path.join(build,'startup.wasm'))});
const c=manifest.case;
m._reset();
for(const r of c.regions)if(m._map_region(r.address,r.size,r.permissions)!==1)throw Error('Invalid PE map region');
const memory=m.HEAPU8.subarray(m._memory_base(),m._memory_base()+m._memory_size());
memory.set(await fs.readFile(path.join(build,manifest.image.url)),manifest.image.address);
for(const w of c.writes)memory.set(w.bytes,w.address);
c.registers.forEach((v,i)=>m._set_reg(i,v));m._set_flags(c.eflags);m._set_eip(c.entry);m._set_fs_base(c.fsBase);
const started=performance.now();
const status=m._run(c.maxSteps,c.stop);
const state={status,steps:m._get_steps(),elapsed_ms:performance.now()-started,
  eip:m._get_eip()>>>0,registers:Array.from({length:8},(_,i)=>m._get_reg(i)>>>0),eflags:m._get_flags()>>>0,
  fault:{code:m._fault_code(),address:m._fault_address()>>>0,message:m.UTF8ToString(m._fault_text())},
  trace:Array.from({length:m._get_trace_count()},(_,i)=>m._get_trace(i)>>>0),
  wasm_memory_bytes:m.HEAPU8.byteLength,gameplay_demonstrated:false,manifest};
await fs.writeFile(path.join(root,'artifacts/startup-node.json'),JSON.stringify(state,null,2)+'\n');
console.log(JSON.stringify({...state,manifest:undefined,trace:state.trace.map(v=>'0x'+v.toString(16))},null,2));
// Reaching a compatibility barrier is evidence, not an exit-code success claim.
if(status!==1)process.exitCode=2;
