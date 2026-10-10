import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from translator.lift import Emitter, Unsupported


class PrefixTests(unittest.TestCase):
    def emit(self, data):
        decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
        insn=next(decoder.disasm(bytes.fromhex(data),0x401000,count=1))
        return Emitter(insn).emit()

    def test_unsupported_address_and_stack_prefixes_fail(self):
        for data in ('66c3','66c9','67e2fd','64a5','67a5','67ab'):
            with self.subTest(data=data),self.assertRaises(Unsupported): self.emit(data)

    def test_xchg_captures_memory_address_before_register_change(self):
        emitted=self.emit('8700') # xchg [eax], eax, assembler's canonical order
        self.assertIn('uint32_t p0=',emitted)
        self.assertLess(emitted.index('uint32_t p0='),emitted.index('write_reg('))

    def test_unknown_instruction_is_not_success(self):
        with self.assertRaises(Unsupported): self.emit('0f0b')


if __name__=='__main__': unittest.main()
