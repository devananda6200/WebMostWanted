// Authored for this project. Compiled to PE32 before any translation.
.intel_syntax noprefix
.text
.globl _arithmetic, _branch, _memory, _calls, _callee, _simd, _x87_load_store
.globl _add_flags, _sub_flags, _adc_flags, _sbb_flags, _byte_flags
.globl _shifts, _copy, _unmapped, _unsupported, _code_write, _indirect_missing
.globl _xchg_alias, _partial_simd_store
.globl _stdcall_call, _stdcall_callee
.globl _sse_movsd_unsupported, _popfd_reserved, _popfd_control_unsupported

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
