// Node executes exactly the same generated modules used by the browser worker.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const build=path.join(root,'build');
const load=async name=>JSON.parse(await fs.readFile(path.join(build,name),'utf8'));
const manifest=await load('manifest.json');

export function initialize(m,c,image=null) {
  m._reset();
  if(m._configure_platform)m._configure_platform(image?.address||0);
  else m._win32_reset?.(image?.address||0);
  for(const region of c.regions) assert.equal(m._map_region(region.address,region.size,region.permissions),1,'map region');
  const memory=m.HEAPU8.subarray(m._memory_base(),m._memory_base()+m._memory_size());
  if(image)memory.set(image.bytes,image.address);
  for(const w of c.writes) memory.set(w.bytes,w.address);
  c.registers.forEach((v,i)=>m._set_reg(i,v));
  c.xmm?.forEach((lanes,i)=>lanes.forEach((v,j)=>m._set_xmm(i,j,v)));
  m._set_flags(c.eflags);m._set_eip(c.entry);
  if(c.fsBase!==undefined)m._set_fs_base(c.fsBase);
  return memory;
}

export function compare(m,c,memory) {
  const expected=c.expected;
  for(let i=0;i<8;i++) assert.equal(m._get_reg(i)>>>0,expected.registers[i],`${c.id}: register ${i}`);
  assert.equal((m._get_flags()&expected.flagsMask)>>>0,(expected.eflags&expected.flagsMask)>>>0,`${c.id}: defined flags`);
  expected.xmm?.forEach((lanes,i)=>lanes.forEach((v,j)=>assert.equal(m._get_xmm(i,j)>>>0,v,`${c.id}: XMM${i}[${j}]`)));
  for(const w of expected.memory) assert.deepEqual([...memory.subarray(w.address,w.address+w.bytes.length)],w.bytes,`${c.id}: memory at 0x${w.address.toString(16)}`);
  assert.equal(m._get_eip()>>>0,c.stop,`${c.id}: return address`);
}

const summary={started_at_utc:new Date().toISOString(),engine:process.version,manifest,suites:[],faultTests:[]};
try {
  for(const suite of manifest.suites) {
    const create=(await import(pathToFileURL(path.join(build,suite.module)))).default;
    const wasmName=suite.module.replace(/\.js$/,'.wasm'),wasmBytes=await fs.readFile(path.join(build,wasmName));
    assert.equal(createHash('sha256').update(wasmBytes).digest('hex'),manifest.artifact_sha256[wasmName],`${suite.id}: Wasm identity`);
    const module=await create({wasmBinary:wasmBytes});
    const {cases}=await load(suite.cases);
    const image=suite.image?{address:suite.image.address,bytes:await fs.readFile(path.join(build,suite.image.url))}:null;
    if(image)assert.equal(createHash('sha256').update(image.bytes).digest('hex'),suite.image.sha256,`${suite.id}: PE image identity`);
    const started=performance.now();
    let executed=0;
    for(const c of cases) {
      const memory=initialize(module,c,image);
      const result=module._run(c.maxSteps,c.stop);
      assert.equal(result,1,`${c.id}: ${module.UTF8ToString(module._fault_text())} at 0x${(module._get_eip()>>>0).toString(16)}`);
      compare(module,c,memory);executed+=module._get_steps();
    }
    const result={id:suite.id,passed:cases.length,total:cases.length,instructions:executed,elapsed_ms:performance.now()-started,wasm_memory_bytes:module.HEAPU8.byteLength};
    summary.suites.push(result);console.log(JSON.stringify(result));
    if(suite.id==='synthetic') {
      for(const c of (await load('fault-cases.json')).cases) {
        const faultMemory=initialize(module,c);
        assert.equal(module._run(c.maxSteps,c.stop),2,c.id);
        assert.equal(module._fault_code(),c.expectedFault,c.id);
        for(const w of c.unchangedOnFault||[])assert.deepEqual([...faultMemory.subarray(w.address,w.address+w.bytes.length)],w.bytes,'faulting store must roll back earlier lanes');
        if(c.id==='unmapped') {
          for(let i=0;i<8;i++)assert.equal(module._get_reg(i)>>>0,c.registers[i],`fault must preserve register ${i}`);
          assert.equal(module._get_eip()>>>0,c.entry,'fault must preserve instruction address');
        }
        summary.faultTests.push({id:c.id,passed:true,code:module._fault_code(),address:module._fault_address()>>>0,message:module.UTF8ToString(module._fault_text())});
      }
    }
  }
  summary.status='passed';
} catch(error) {summary.status='failed';summary.error=error.stack;process.exitCode=1;console.error(error);}
summary.finished_at_utc=new Date().toISOString();
await fs.writeFile(path.join(root,'artifacts/wasm-tests.json'),JSON.stringify(summary,null,2)+'\n');
