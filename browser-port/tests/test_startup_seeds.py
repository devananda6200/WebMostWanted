"""Authored seed inputs and fake PE mappings; no compilation or game execution."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import build_startup as startup
from tools.toolchain import ROOT, node_path


class FakeImage:
    def __init__(self):
        self.base=0x400000
        self.entry=self.base+0x1000
        self.size=0x5000
        self.data=b'authored header'.ljust(0x200,b'\0')+b'\xc3'*0x2000
        self.sha256=hashlib.sha256(self.data).hexdigest()
        self.pe=SimpleNamespace(
            sections=[SimpleNamespace(VirtualAddress=0x1000,Misc_VirtualSize=0x3000,
                                      SizeOfRawData=0x2000,PointerToRawData=0x200,Characteristics=0x60000020)],
            DIRECTORY_ENTRY_IMPORT=[],get_memory_mapped_image=lambda:self.data)

    def executable(self,address):
        return self.entry<=address<self.entry+0x2000

    def regions(self):
        return []


class SeedValidationTests(unittest.TestCase):
    def setUp(self):
        self.image=FakeImage()

    def test_addresses_are_deduplicated_and_sorted(self):
        first=self.image.entry
        self.assertEqual(startup.validate_seeds(self.image,[first+3,first,first+3]),[first,first+3])
        self.assertEqual(startup.validate_seeds(self.image,[]),[])

    def test_malformed_lists_and_addresses_are_rejected(self):
        for value in (None,{},'[]',(self.image.entry,)):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'JSON list'):
                startup.validate_seeds(self.image,value)
        for value in (True,False,-1,2**32,1.5,'0x401000',None):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'uint32'):
                startup.validate_seeds(self.image,[value])

    def test_virtual_tail_nonexec_and_truncated_backing_are_rejected(self):
        for address in (0,self.image.entry-1,self.image.entry+0x2000):
            with self.subTest(address=address),self.assertRaisesRegex(ValueError,'file-backed'):
                startup.validate_seeds(self.image,[address])
        self.image.pe.sections[0].Characteristics=0x40000040
        with self.assertRaisesRegex(ValueError,'executable'):
            startup.validate_seeds(self.image,[self.image.entry])
        self.image.pe.sections[0].Characteristics=0x60000020
        self.image.data=self.image.data[:0x200]
        with self.assertRaisesRegex(ValueError,'truncated'):
            startup.validate_seeds(self.image,[self.image.entry])

    def test_ambiguous_file_backing_is_rejected(self):
        self.image.pe.sections.append(copy.copy(self.image.pe.sections[0]))
        with self.assertRaisesRegex(ValueError,'unambiguous'):
            startup.validate_seeds(self.image,[self.image.entry])


class SeedFilesTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.project=self.root/'project with spaces'
        self.game=self.root/'read only authored inputs'
        for path in (self.project/'generated',self.project/'build',self.project/'artifacts',self.game):
            path.mkdir(parents=True)
        self.image=FakeImage()
        self.default=self.project/startup.SEEDS_RELATIVE
        self.saved={'input_sha256':self.image.sha256,'seeds':[self.image.entry+9],'note':'preserve'}
        self.write_json(self.default,self.saved)
        self.binary=self.game/'speed.exe'
        self.binary.write_bytes(self.image.data)

    @staticmethod
    def write_json(path,value):
        path.write_text(json.dumps(value),encoding='utf-8')

    def snapshot(self,seeds=None):
        return startup.save_seed_snapshot(self.image,seeds or [self.image.entry],self.project,self.game)

    def link(self,path,target,is_directory=False):
        try:path.symlink_to(target,target_is_directory=is_directory)
        except OSError as exc:self.skipTest(f'Symbolic links unavailable: {exc}')

    def test_default_progress_is_preserved_and_atomically_updated(self):
        seeds,source=startup.load_seeds(self.image,self.project)
        self.assertEqual(seeds,self.saved['seeds'])
        startup.save_default_seeds(source,[self.image.entry,*seeds],self.project,self.game)
        self.assertEqual(json.loads(self.default.read_text()),{**self.saved,'seeds':[self.image.entry,*seeds]})
        self.assertEqual(self.binary.read_bytes(),self.image.data)
        self.assertFalse(list(self.project.rglob('*.tmp')))

    def test_missing_default_is_empty_but_explicit_missing_is_error(self):
        self.default.unlink()
        seeds,source=startup.load_seeds(self.image,self.project)
        self.assertEqual(seeds,[])
        self.assertIsNone(source['original'])
        startup.save_default_seeds(source,[],self.project,self.game)
        self.assertEqual(json.loads(self.default.read_text()),{'input_sha256':self.image.sha256,'seeds':[]})
        with self.assertRaisesRegex(ValueError,'does not exist'):
            startup.load_seeds(self.image,self.project,'missing.json')

    def test_explicit_file_replaces_default_and_neither_is_overwritten(self):
        explicit=self.project/"author's seed file.json"
        self.write_json(explicit,{'input_sha256':self.image.sha256,'seeds':[self.image.entry]})
        before=explicit.read_bytes(),self.default.read_bytes()
        seeds,source=startup.load_seeds(self.image,self.project,explicit.name)
        self.assertEqual(seeds,[self.image.entry])
        startup.save_default_seeds(source,seeds+[self.image.entry+1],self.project,self.game)
        self.assertEqual(before,(explicit.read_bytes(),self.default.read_bytes()))
        # Explicitly naming the default file still makes that input read-only.
        _,source=startup.load_seeds(self.image,self.project,self.default)
        startup.save_default_seeds(source,[],self.project,self.game)
        self.assertEqual(self.default.read_bytes(),before[1])

    def test_malformed_hash_mismatch_and_duplicate_fields_are_rejected(self):
        cases=[b'{',b'[]',b'null',b'\xff',json.dumps({'input_sha256':'0'*64,'seeds':[]}).encode(),
               json.dumps({'input_sha256':self.image.sha256,'seeds':[True]}).encode(),
               ('{"input_sha256":"'+self.image.sha256+'","seeds":[],"seeds":[]}').encode()]
        for raw in cases:
            self.default.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                startup.load_seeds(self.image,self.project)
            self.assertEqual(self.default.read_bytes(),raw)

    def test_snapshot_is_content_addressed_and_reused_without_overwrite(self):
        snapshot=self.snapshot([self.image.entry+2,self.image.entry,self.image.entry])
        path=self.project/snapshot['path']
        before=path.read_bytes(),path.stat().st_mtime_ns
        self.assertEqual(snapshot['sha256'],hashlib.sha256(before[0]).hexdigest())
        self.assertEqual(path.stem,snapshot['sha256'])
        self.assertEqual(snapshot['count'],2)
        self.assertEqual(json.loads(before[0]),{'input_sha256':self.image.sha256,'seeds':[self.image.entry,self.image.entry+2]})
        self.assertEqual(self.snapshot([self.image.entry+2,self.image.entry]),snapshot)
        self.assertEqual(before,(path.read_bytes(),path.stat().st_mtime_ns))
        self.assertEqual(startup.load_seeds(self.image,self.project,snapshot['path'])[0],
                         [self.image.entry,self.image.entry+2])

    def test_modified_snapshot_is_rejected_on_read_and_reuse(self):
        snapshot=self.snapshot()
        path=self.project/snapshot['path']
        path.write_bytes(b'{"tampered":true}')
        for operation in (lambda:startup.load_seeds(self.image,self.project,path),self.snapshot):
            with self.assertRaisesRegex(ValueError,'SHA-256 filename'):
                operation()
        self.assertEqual(path.read_bytes(),b'{"tampered":true}')

    def test_concurrent_input_update_is_preserved(self):
        _,source=startup.load_seeds(self.image,self.project)
        newer={**self.saved,'seeds':[self.image.entry+10]}
        self.write_json(self.default,newer)
        with self.assertRaisesRegex(ValueError,'changed during compilation'):
            startup.save_default_seeds(source,[],self.project,self.game)
        self.assertEqual(json.loads(self.default.read_text()),newer)

    def test_read_only_installation_and_output_traversal_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'read-only installation'):
            startup.output_path(self.game/'nested project',self.game,startup.SEEDS_RELATIVE)
        for relative in ('../outside.json','generated/../outside.json','tools/source.py',str(self.root/'outside.json')):
            with self.subTest(relative=relative),self.assertRaisesRegex(ValueError,'designated ignored'):
                startup.output_path(self.project,self.game,relative)

    def test_explicit_seed_cannot_alias_another_build_output(self):
        output=self.project/'build/startup.json'
        self.write_json(output,self.saved)
        _,source=startup.load_seeds(self.image,self.project,output)
        with self.assertRaisesRegex(ValueError,'would be overwritten'):
            startup.check_build_outputs(self.project,self.game,source)

    def test_seed_input_and_default_output_file_links_are_rejected(self):
        self.default.unlink()
        target=self.root/'outside.json'
        self.write_json(target,self.saved)
        self.link(self.default,target)
        before=target.read_bytes()
        with self.assertRaisesRegex(ValueError,'links'):
            startup.load_seeds(self.image,self.project)
        with self.assertRaisesRegex(ValueError,'link'):
            startup.output_path(self.project,self.game,startup.SEEDS_RELATIVE)
        self.assertEqual(target.read_bytes(),before)

    def test_snapshot_directory_link_cannot_redirect_writes(self):
        self.link(self.project/startup.SNAPSHOTS_RELATIVE,self.game,True)
        with self.assertRaisesRegex(ValueError,'read-only installation'):
            self.snapshot()
        self.assertEqual([p.name for p in self.game.iterdir()],['speed.exe'])

    def test_snapshot_file_link_is_rejected_without_touching_target(self):
        snapshot=self.snapshot()
        path=self.project/snapshot['path']
        data=path.read_bytes()
        target=self.root/'external-snapshot.json'
        target.write_bytes(data)
        path.unlink()
        self.link(path,target)
        with self.assertRaisesRegex(ValueError,'link'):
            self.snapshot()
        self.assertEqual(target.read_bytes(),data)

    def test_writable_hard_link_is_rejected(self):
        target=self.root/'outside.json'
        self.write_json(target,self.saved)
        self.default.unlink()
        try:os.link(target,self.default)
        except OSError as exc:self.skipTest(f'Hard links unavailable: {exc}')
        with self.assertRaisesRegex(ValueError,'hard links'):
            startup.output_path(self.project,self.game,startup.SEEDS_RELATIVE)
        self.assertEqual(json.loads(target.read_text()),self.saved)

    def mock_prepare(self,**kwargs):
        # Only the orchestration runs. No compiler, native binary, or original
        # game data participates in these authored fixture tests.
        for name in ('translator/lift.py','runtime/guest.hpp','runtime/win32.hpp',
                     'tools/build_startup.py','tools/build_tests.py','tools/toolchain.py'):
            path=self.project/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('authored provenance placeholder\n')
        def fake_wasm(*args,**options):
            (self.project/'build/startup.wasm').write_bytes(b'authored compiler stand-in')
        report={'instruction_count':2,'unsupported':[],'untranslated_targets':[]}
        with patch.object(startup,'ROOT',self.project),patch.object(startup,'EXE_SHA',self.image.sha256),\
             patch.object(startup,'load_game_root',return_value=self.game),patch.object(startup,'PEImage',return_value=self.image),\
             patch.object(startup,'lift',return_value=report) as lifter,patch.object(startup,'wasm',side_effect=fake_wasm) as compiler,\
             contextlib.redirect_stdout(io.StringIO()):
            manifest=startup.prepare(**kwargs)
        return manifest,lifter,compiler

    def test_build_orchestration_records_snapshot_and_explicit_input_is_immutable(self):
        snapshot=self.snapshot()
        path=self.project/snapshot['path']
        before=path.read_bytes(),path.stat().st_mtime_ns,self.default.read_bytes()
        manifest,lifter,compiler=self.mock_prepare(seed_file=path,extra_seeds=[self.image.entry+1])
        self.assertEqual(compiler.call_count,1)
        self.assertEqual(lifter.call_args.args[1],[self.image.entry,self.image.entry,self.image.entry+1])
        self.assertEqual(manifest['provenance']['seeds'],[self.image.entry,self.image.entry+1])
        recorded=manifest['provenance']['seed_snapshot']
        self.assertEqual(recorded['count'],2)
        self.assertEqual(hashlib.sha256((self.project/recorded['path']).read_bytes()).hexdigest(),recorded['sha256'])
        self.assertEqual(before,(path.read_bytes(),path.stat().st_mtime_ns,self.default.read_bytes()))

    def test_default_build_merges_manual_progress_and_snapshots_exact_result(self):
        manifest,_,_=self.mock_prepare(extra_seeds=[self.image.entry+1])
        seeds=[self.image.entry+1,self.image.entry+9]
        self.assertEqual(manifest['provenance']['seeds'],seeds)
        self.assertEqual(json.loads(self.default.read_text()),{**self.saved,'seeds':seeds})
        snapshot=self.project/manifest['provenance']['seed_snapshot']['path']
        self.assertEqual(json.loads(snapshot.read_text())['seeds'],seeds)

    def test_invalid_seed_fails_before_translation_or_compilation(self):
        self.write_json(self.default,{**self.saved,'seeds':[self.image.entry+0x2000]})
        before=self.default.read_bytes()
        with self.assertRaisesRegex(ValueError,'file-backed'):
            self.mock_prepare()
        self.assertEqual(before,self.default.read_bytes())
        self.assertFalse((self.project/'build/game-image.bin').exists())
        self.assertFalse((self.project/'build/startup.wasm').exists())


class ReproductionTests(unittest.TestCase):
    setUp=SeedFilesTests.setUp
    write_json=staticmethod(SeedFilesTests.write_json)
    snapshot=SeedFilesTests.snapshot

    def run_node(self,manifest,verify=False):
        try:node=node_path()
        except FileNotFoundError as exc:self.skipTest(str(exc))
        module=(ROOT/'tests/run_startup.mjs').as_uri()
        expression='await m.verifySeedSnapshot(value,process.argv[1])' if verify else 'm.reproductionFor(value)'
        code=f"import {{readFileSync}} from 'node:fs'; const m=await import({json.dumps(module)}); const value=JSON.parse(readFileSync(0,'utf8')); console.log(JSON.stringify({expression}));"
        return subprocess.run([str(node),'--input-type=module','--eval',code,str(self.project)],input=json.dumps(manifest),
                              cwd=ROOT,text=True,capture_output=True,timeout=20)

    def manifest(self):
        seeds=list(range(self.image.entry,self.image.entry+7000))
        snapshot=self.snapshot(seeds)
        return {'provenance':{'seed_snapshot':snapshot,'instruction_limit':24000,'seeds':seeds,
                              'executable_sha256':self.image.sha256},'case':{'maxSteps':3000000}}

    def test_seven_thousand_seeds_produce_compact_verified_command(self):
        manifest=self.manifest()
        result=self.run_node(manifest,verify=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reproduction=json.loads(result.stdout)
        command=reproduction['build']
        self.assertLess(len(command),350)
        self.assertIn("--seed-file 'artifacts/startup-seeds/",command)
        self.assertNotIn('--seed 0x',command)
        self.assertIn('--limit 24000 --max-steps 3000000',command)

    def test_missing_snapshot_is_explicitly_unavailable_for_old_build(self):
        result=self.run_node({'provenance':{},'case':{'maxSteps':1}})
        self.assertEqual(result.returncode,0,result.stderr)
        reproduction=json.loads(result.stdout)
        self.assertIsNone(reproduction['build'])
        self.assertIn('predates',reproduction['unavailable_reason'])

    def test_untrusted_path_or_numeric_arguments_cannot_inject_command(self):
        manifest=self.manifest()
        for path in ('../escape.json',"artifacts/startup-seeds/a'; malicious-command; '.json"):
            changed=copy.deepcopy(manifest)
            changed['provenance']['seed_snapshot']['path']=path
            result=self.run_node(changed)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Invalid startup seed snapshot',result.stderr)
        manifest['provenance']['instruction_limit']='24000; malicious-command'
        result=self.run_node(manifest)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Invalid startup seed snapshot',result.stderr)

    def test_snapshot_bytes_and_manifest_binding_are_verified(self):
        manifest=self.manifest()
        path=self.project/manifest['provenance']['seed_snapshot']['path']
        original=path.read_bytes()
        path.write_bytes(original+b' ')
        result=self.run_node(manifest,verify=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('identity mismatch',result.stderr)
        path.write_bytes(original)
        manifest['provenance']['executable_sha256']='0'*64
        result=self.run_node(manifest,verify=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('differs from the build manifest',result.stderr)


if __name__=='__main__':
    unittest.main()
