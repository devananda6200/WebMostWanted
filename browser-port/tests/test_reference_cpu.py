"""Verify the isolated oracle's OS state, including its real exception path."""
import unittest
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_ERR_EXCEPTION
from unicorn import x86_const as x86
from tools.build_tests import configure_reference_cpu


class ReferenceCpuTests(unittest.TestCase):
    def cpu(self, code, control, status):
        cpu = Uc(UC_ARCH_X86, UC_MODE_32)
        configure_reference_cpu(cpu)
        cpu.mem_map(0x1000, 4096)
        cpu.mem_write(0x1000, bytes.fromhex(code))
        cpu.reg_write(x86.UC_X86_REG_FPCW, control)
        cpu.reg_write(x86.UC_X86_REG_FPSW, status)
        return cpu

    def test_unmasked_wait_raises_at_the_faulting_instruction(self):
        cpu = self.cpu('9b90', 0x037e, 0x0081)
        with self.assertRaises(UcError) as caught:
            cpu.emu_start(0x1000, 0x1002)
        self.assertEqual(caught.exception.errno, UC_ERR_EXCEPTION)
        self.assertEqual(cpu.reg_read(x86.UC_X86_REG_EIP), 0x1000)

    def test_masked_wait_completes(self):
        cpu = self.cpu('9b90', 0x037f, 0x0001)
        cpu.emu_start(0x1000, 0x1002)
        self.assertEqual(cpu.reg_read(x86.UC_X86_REG_EIP), 0x1002)

    def test_fnclex_clears_pending_exception_before_wait(self):
        cpu = self.cpu('dbe29b90', 0x037e, 0x0081)
        cpu.emu_start(0x1000, 0x1004)
        self.assertEqual(cpu.reg_read(x86.UC_X86_REG_FPSW) & 0x80ff, 0)
        self.assertEqual(cpu.reg_read(x86.UC_X86_REG_EIP), 0x1004)
