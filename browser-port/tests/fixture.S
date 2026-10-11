// Authored for this project. Compiled to PE32 before any translation.
.intel_syntax noprefix
.text
.globl _arithmetic, _branch, _memory, _calls, _callee, _simd, _x87_load_store
.globl _add_flags, _sub_flags, _adc_flags, _sbb_flags, _byte_flags
.globl _shifts, _copy, _unmapped, _unsupported, _code_write, _indirect_missing
.globl _xchg_alias, _partial_simd_store
.globl _stdcall_call, _stdcall_callee
.globl _sse_movsd_unsupported, _popfd_reserved, _popfd_control_unsupported
.globl _x87_control, _x87_clear, _x87_init, _x87_wait, _x87_rounded_store
.globl _cpuid_detect
.globl _cpu_features
.globl _idiv32_ecx, _idiv32_eax, _idiv32_edx, _idiv32_mem, _idiv32_pointer
.globl _div32_ecx, _div32_eax, _div32_edx, _div32_mem, _div32_pointer
.globl _idiv16_unsupported, _div8_unsupported
.globl _shld32_cl, _shld32_imm, _shld32_mem, _shld32_alias
.globl _shrd32_cl, _shrd32_imm, _shrd32_mem, _shrd32_alias
.globl _shld16_unsupported
.globl _x87_abs, _x87_abs_compare, _x87_compare64, _x87_compare_empty
.globl _x87_abs_empty
.globl _x87_add32, _x87_add64, _x87_sub32, _x87_sub64, _x87_add_empty, _x87_sub_empty
.globl _x87_mul32, _x87_mul64, _x87_mul_empty

_arithmetic:
    push ebp
    mov ebp, esp
    mov eax, dword ptr [ebp+8]
    mov ecx, dword ptr [ebp+12]
    add eax, ecx
    seto dl
    setb dh
    pushfd
    pop ebx
    adc eax, 17
    sub eax, 7
    imul eax, eax, 33
    xor eax, 0xa53b198f
    leave
    ret
_branch:
    mov eax, dword ptr [esp+4]
    mov ecx, dword ptr [esp+8]
    cmp eax, ecx
    jge positive
    neg eax
positive:
    test eax, 1
    je even
    add eax, 11
    jmp branch_done
even:
    sub eax, 13
branch_done:
    ret
_memory:
    mov edi, dword ptr [esp+4]
    mov esi, dword ptr [esp+8]
    mov ecx, 8
memory_loop:
    mov eax, dword ptr [esi+ecx*4-4]
    xor eax, 0xdeadbeef
    mov dword ptr [edi+ecx*4-4], eax
    dec ecx
    jne memory_loop
    lea eax, [edi+32]
    ret
_calls:
    mov eax, dword ptr [esp+4]
    call _callee
    mov edx, offset _callee
    call edx
    ret
_callee:
    lea eax, [eax+eax*4+3]
    ret
_simd:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    movups xmm0, xmmword ptr [esi]
    movups xmm1, xmmword ptr [esi+16]
    addps xmm0, xmm1
    mulps xmm0, xmm1
    movups xmmword ptr [edi], xmm0
    movss xmm2, dword ptr [esi+32]
    addss xmm2, xmm1
    cvttss2si eax, xmm2
    movss dword ptr [edi+16], xmm2
    ret
_x87_load_store:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    fld dword ptr [esi]
    fstp qword ptr [edi]
    fld qword ptr [edi]
    fstp dword ptr [edi+8]
    ret
_add_flags:
    mov eax, dword ptr [esp+4]
    add eax, dword ptr [esp+8]
    ret
_sub_flags:
    mov eax, dword ptr [esp+4]
    sub eax, dword ptr [esp+8]
    ret
_adc_flags:
    mov eax, dword ptr [esp+4]
    adc eax, dword ptr [esp+8]
    ret
_sbb_flags:
    mov eax, dword ptr [esp+4]
    sbb eax, dword ptr [esp+8]
    ret
_byte_flags:
    mov eax, dword ptr [esp+4]
    mov ecx, dword ptr [esp+8]
    add al, cl
    sbb ah, ch
    ret
_shifts:
    mov eax, dword ptr [esp+4]
    mov ecx, dword ptr [esp+8]
    shl eax, cl
    shr eax, 1
    sar eax, 1
    ret
_copy:
    mov edi, dword ptr [esp+4]
    mov esi, dword ptr [esp+8]
    mov ecx, 8
    cld
    rep movsd
    ret
_unmapped:
    mov eax, dword ptr [0x3ffffff]
    ret
_unsupported:
    ud2
    ret
_code_write:
    mov eax, offset _code_write
    mov byte ptr [eax], 0x90
    ret
_indirect_missing:
    mov eax, dword ptr [esp+4]
    call eax
    ret
_xchg_alias:
    mov eax, dword ptr [esp+4]
    xchg dword ptr [eax], eax
    ret
_partial_simd_store:
    mov edi, dword ptr [esp+4]
    movups xmmword ptr [edi], xmm0
    ret
_stdcall_call:
    mov edi, dword ptr [esp+4]
    mov eax, offset _stdcall_callee
    mov dword ptr [edi], eax
    push 19
    call dword ptr [edi]
    ret
_stdcall_callee:
    mov eax, dword ptr [esp+4]
    add eax, 23
    ret 4
_sse_movsd_unsupported:
    movsd qword ptr [eax], xmm0
    ret
_popfd_reserved:
    push dword ptr [esp+4]
    popfd
    pushfd
    pop eax
    ret
_popfd_control_unsupported:
    push 0x302
    popfd
    ret
_x87_control:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    fnstcw word ptr [edi]
    fldcw word ptr [esi]
    fnstcw word ptr [edi+2]
    fnclex
    wait
    fnstsw word ptr [edi+4]
    fnstsw ax
    ret
_x87_clear:
    mov edi, dword ptr [esp+4]
    fnstsw word ptr [edi]
    fnclex
    wait
    fnstcw word ptr [edi+2]
    fnstsw word ptr [edi+4]
    fnstsw ax
    ret
_x87_init:
    mov edi, dword ptr [esp+4]
    fninit
    fnstcw word ptr [edi]
    fnstsw word ptr [edi+2]
    fld1
    fnstsw word ptr [edi+4]
    fstp qword ptr [edi+8]
    fnstsw word ptr [edi+6]
    ret
_x87_wait:
    wait
    ret
_x87_rounded_store:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    fld qword ptr [esi]
    fstp dword ptr [edi]
    ret
_cpuid_detect:
    pushfd
    pop ecx
    mov eax, ecx
    xor eax, 0x00200000
    push eax
    popfd
    pushfd
    pop eax
    xor eax, ecx
    push ecx
    popfd
    ret
_cpu_features:
    mov eax, dword ptr [esp+4]
    mov ecx, dword ptr [esp+8]
    cpuid
    ret
_idiv32_ecx:
    idiv ecx
    ret
_idiv32_eax:
    idiv eax
    ret
_idiv32_edx:
    idiv edx
    ret
_idiv32_mem:
    idiv dword ptr [esp+4]
    ret
_idiv32_pointer:
    idiv dword ptr [eax]
    ret
_div32_ecx:
    div ecx
    ret
_div32_eax:
    div eax
    ret
_div32_edx:
    div edx
    ret
_div32_mem:
    div dword ptr [esp+4]
    ret
_div32_pointer:
    div dword ptr [eax]
    ret
_idiv16_unsupported:
    idiv cx
    ret
_div8_unsupported:
    div cl
    ret
_shld32_cl:
    shld eax, edx, cl
    ret
_shld32_imm:
    shld eax, edx, 9
    ret
_shld32_mem:
    shld dword ptr [esi], edx, cl
    ret
_shld32_alias:
    shld ecx, ecx, cl
    ret
_shrd32_cl:
    shrd eax, edx, cl
    ret
_shrd32_imm:
    shrd eax, edx, 9
    ret
_shrd32_mem:
    shrd dword ptr [esi], edx, cl
    ret
_shrd32_alias:
    shrd ecx, ecx, cl
    ret
_shld16_unsupported:
    shld ax, dx, cl
    ret
_x87_abs:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    fld qword ptr [esi]
    fabs
    fnstsw ax
    fstp qword ptr [edi]
    ret
_x87_abs_compare:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    fld qword ptr [esi]
    fabs
    fcomp dword ptr [edi]
    fnstsw ax
    ret
_x87_compare64:
    mov esi, dword ptr [esp+4]
    mov edi, dword ptr [esp+8]
    fld qword ptr [esi]
    fcom qword ptr [edi]
    fnstsw ax
    fstp qword ptr [edi+8]
    ret
_x87_compare_empty:
    fcomp dword ptr [esi]
    ret
_x87_abs_empty:
    fabs
    ret

.macro exact_x87 name, operation, width
_\name:
    mov ecx, dword ptr [esp+4]
    mov edx, dword ptr [esp+8]
    fld qword ptr [ecx]
    \operation \width ptr [ecx+8]
    fnstsw ax
    fstp qword ptr [edx]
    ret
.endm
exact_x87 x87_add32, fadd, dword
exact_x87 x87_add64, fadd, qword
exact_x87 x87_sub32, fsub, dword
exact_x87 x87_sub64, fsub, qword
exact_x87 x87_mul32, fmul, dword
exact_x87 x87_mul64, fmul, qword
_x87_add_empty:
    fadd dword ptr [esi]
    ret
_x87_sub_empty:
    fsub dword ptr [esi]
    ret
_x87_mul_empty:
    fmul dword ptr [esi]
    ret
