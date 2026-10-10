import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

export function reproductionFor(manifest){
  const run='.\\.tools\\emsdk-4.0.23\\node\\22.16.0_64bit\\bin\\node.exe tests/run_startup.mjs';
  const p=manifest.provenance, snapshot=p?.seed_snapshot;
  if(!snapshot)return {build:null,run,unavailable_reason:'This build predates immutable seed snapshots; rebuild with the current tools.'};
  if(!/^[0-9a-f]{64}$/.test(snapshot.sha256)||snapshot.path!==`artifacts/startup-seeds/${snapshot.sha256}.json`
    ||!Number.isSafeInteger(snapshot.count)||snapshot.count<0||!Array.isArray(p.seeds)||snapshot.count!==p.seeds.length
    ||!Number.isSafeInteger(p.instruction_limit)||p.instruction_limit<1
    ||!Number.isSafeInteger(manifest.case?.maxSteps)||manifest.case.maxSteps<1||manifest.case.maxSteps>10000000){
    throw Error('Invalid startup seed snapshot/build reproduction metadata');
  }
  // PowerShell single-quoted arguments preserve spaces and disable expansion.
  const seedArgument="'"+snapshot.path.replaceAll("'","''")+"'";
  return {build:`.\\.venv\\Scripts\\python.exe -m tools.build_startup --limit ${p.instruction_limit} --max-steps ${manifest.case.maxSteps} --seed-file ${seedArgument}`,run};
}

export async function verifySeedSnapshot(manifest,projectRoot){
  const reproduction=reproductionFor(manifest);
  const snapshot=manifest.provenance?.seed_snapshot;
  if(!snapshot)return reproduction;
  const bytes=await fs.readFile(path.join(projectRoot,snapshot.path));
  if(createHash('sha256').update(bytes).digest('hex')!==snapshot.sha256)throw Error('Startup seed snapshot identity mismatch');
  const saved=JSON.parse(bytes);
  if(saved.input_sha256!==manifest.provenance.executable_sha256||JSON.stringify(saved.seeds)!==JSON.stringify(manifest.provenance.seeds)){
    throw Error('Startup seed snapshot differs from the build manifest');
  }
  return reproduction;
}

async function main(){
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const build=path.join(root,'build');
const manifest=JSON.parse(await fs.readFile(path.join(build,'startup.json'),'utf8'));
const reproduction=await verifySeedSnapshot(manifest,root);
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
  fpu:{control:m._get_fpu_control(),status:m._get_fpu_status(),depth:m._get_fpu_depth(),valueFormat:'exact-binary64-subset',
    values:Array.from({length:m._get_fpu_depth()},(_,i)=>[m._get_fpu_bits(i,0)>>>0,m._get_fpu_bits(i,1)>>>0])},
  fault:{code:m._fault_code(),address:m._fault_address()>>>0,message:m.UTF8ToString(m._fault_text())},
  trace:Array.from({length:m._get_trace_count()},(_,i)=>m._get_trace(i)>>>0),
  wasm_memory_bytes:m.HEAPU8.byteLength,gameplay_demonstrated:false,manifest};
const stack=state.registers[4];
state.stack_words=stack+48<=memory.byteLength?Array.from({length:12},(_,i)=>new DataView(memory.buffer,memory.byteOffset+stack+i*4,4).getUint32(0,true)):[];
// Capture a small, private diagnostic window without changing guest state.
// Faulting NLS/buffer operations need their actual input bytes, not an inferred
// value based only on the disassembled call site.
if(state.fault.code && state.fault.address<memory.byteLength){
  const address=Math.max(0,state.fault.address-16);
  state.fault_memory={address,bytes:Array.from(memory.subarray(address,Math.min(address+64,memory.byteLength)))};
}
state.reproduction=reproduction;
await fs.writeFile(path.join(root,'artifacts/startup-node.json'),JSON.stringify(state,null,2)+'\n');
await fs.appendFile(path.join(root,'artifacts/startup-history.jsonl'),JSON.stringify(state)+'\n');
console.log(JSON.stringify({status,steps:state.steps,elapsed_ms:state.elapsed_ms,eip:'0x'+state.eip.toString(16),fault:state.fault,
  trace_tail:state.trace.slice(-8).map(v=>'0x'+v.toString(16)),wasm_memory_bytes:state.wasm_memory_bytes,gameplay_demonstrated:false},null,2));
// Reaching a compatibility barrier is evidence, not an exit-code success claim.
if(status!==1)process.exitCode=2;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)await main();
