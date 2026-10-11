import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'evidence', 'hash32');
const wasm = fs.readFileSync(path.join(output, 'hash32.wasm'));
const { instance } = await WebAssembly.instantiate(wasm);
const inputMemory = new Uint8Array(instance.exports.memory.buffer);
const cases = JSON.parse(fs.readFileSync(path.join(output, 'reference.json'), 'utf8'));
for (const test of cases) {
  const bytes = Buffer.from(test.input_hex, 'hex');
  inputMemory.set(bytes, 1024);
  inputMemory[1024 + bytes.length] = 0;
  const result = instance.exports.nfsmw_hash32(1024) >>> 0;
  if (result !== test.expected) throw new Error(`Case ${test.index}: ${result} != ${test.expected}`);
  if (!Buffer.from(inputMemory.slice(1024, 1024 + bytes.length)).equals(bytes) || inputMemory[1024 + bytes.length] !== 0) {
    throw new Error(`Case ${test.index}: input was modified`);
  }
}
const result = {
  created_utc: new Date().toISOString(),
  routine_va: '0x00460bf0',
  passed: cases.length,
  failed: 0,
  wasm_sha256: createHash('sha256').update(wasm).digest('hex'),
  source_sha256: createHash('sha256').update(fs.readFileSync(path.join(root, 'reconstructed', 'hash32.c'))).digest('hex'),
  reference: 'Original 33 x86 bytes executed in Unicorn 2.1.4',
  scope: 'Return value and unchanged input for valid NUL-terminated byte buffers; not scratch registers, flags, faults, timing or complete game.'
};
fs.writeFileSync(path.join(output, 'validation.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
