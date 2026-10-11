# Floating-point implementation boundaries

## Current runtime

The runtime currently stores x87 values as binary64 (`double`), with explicit
control/status state and fail-stop restrictions on unsupported values or
rounding. A bounded, exact-binary64 `FADD`/`FSUB`/`FMUL` bridge is implemented and has
passed binary reference tests. This is not full x87 arithmetic: an extended result that
cannot be represented exactly by the current storage must remain unsupported.
See [verified status](VERIFIED_STATUS.md) for the latest integration evidence.

## SoftFloat assessment

**Status: Proposed runtime integration; isolated library build in progress.**
Primary-source documentation and upstream identity were inspected, and the
pinned source was downloaded locally. The separate harness is not integrated
into gameplay. Emscripten compatibility, performance, and x87 differential
results must be recorded before making an arithmetic correctness claim.

Candidate: Berkeley SoftFloat Release 3e, pinned to upstream revision
`a0c6494cdc11865811dec815d5c0049fba9d82a8` (2025-03-07). This is a pinned upstream
revision identifying itself as 3e, not a claimed hash of the original release
archive. Identity was checked with `git ls-remote` and the GitHub commit API.
The [pinned license](https://raw.githubusercontent.com/ucb-bar/berkeley-softfloat-3/a0c6494cdc11865811dec815d5c0049fba9d82a8/COPYING.txt)
is BSD-3-Clause; retain the notices in source and distributed binary materials.

SoftFloat supplies extended-format add, subtract, multiply, divide, conversions,
and explicit rounding controls using integer arithmetic. It is a candidate
arithmetic backend, not an x87 instruction emulator.
[Official interface](https://www.jhauser.us/arithmetic/SoftFloat-3/doc/SoftFloat.html)

## Proposed Emscripten 4.0.23 build

Use the explicit object manifest in
[`build/template-FAST_INT64/Makefile`](https://raw.githubusercontent.com/ucb-bar/berkeley-softfloat-3/a0c6494cdc11865811dec815d5c0049fba9d82a8/build/template-FAST_INT64/Makefile),
with `source/8086` specialization. Do not recursively compile conflicting
specializations. Compile `.c` files as C with `tools.toolchain.emcc_command(False)`
and `toolchain_env()`, then archive and link into the C++ runtime.

Initial options: `-std=c11 -O2 -DSOFTFLOAT_FAST_INT64 -DINLINE_LEVEL=0`, with
include paths for a local `platform.h`, `source/8086`, and `source/include`.
Define `LITTLEENDIAN 1` in that platform header. Use ordinary globals for the
current single guest thread; reconsider mode-state ownership before adding
threads. Avoid native assembly optimizations initially. The C++ caller needs
`extern "C"` around `softfloat.h` and matching `SOFTFLOAT_FAST_INT64` configuration.
[Official porting documentation](https://www.jhauser.us/arithmetic/SoftFloat-3/doc/SoftFloat-source.html)

Relevant sources include `source/extF80_{add,sub,mul,div}.c`,
`s_{addMags,subMags,normRoundPackTo,roundPackTo}ExtF80.c`, their primitive helpers,
`softfloat_state.c`, and the selected specialization. This shortlist is not a
verified minimal link closure; the template supplies the complete object list.

## Guest state and control mapping

Store registers and transaction snapshots as full `extFloat80_t` values before
enabling general extended arithmetic. Converting intermediate results through
`double` loses information. Explicitly pack/unpack the guest's 10-byte values;
host structure size/order can include padding.

| x87 control | SoftFloat setting |
| --- | --- |
| PC `00`: 24 significand bits | `extF80_roundingPrecision = 32` |
| PC `10`: 53 significand bits | `extF80_roundingPrecision = 64` |
| PC `11`: 64 significand bits | `extF80_roundingPrecision = 80` |
| PC `01` | Reserved; reject until verified |
| RC nearest / down / up / truncate | `softfloat_round_near_even` / `softfloat_round_min` / `softfloat_round_max` / `softfloat_round_minMag` |

Thus observed control word `0x027f` requires SoftFloat precision `64`, while
retaining the extended exponent range. Validate canonical extended encodings
before arithmetic; SoftFloat does not guarantee noncanonical-input behavior.
[Interface sections 4.4 and 6](https://www.jhauser.us/arithmetic/SoftFloat-3/doc/SoftFloat.html),
[Intel SDM section 8.1.5](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366521.pdf)

The native authored probe (`tools.native_fpu_reference`) measures reserved-bit
readback as `(input & 0x1f3f) | 0x40` on this AMD host: loading `0x023f` reads
back `0x027f`. All 18 control cases follow that rule; 15 differ from raw Unicorn.
FNINIT and a constant-return process probe also pass. The runtime declares this
profile and retains reference adjustments explicitly. Intel's reserved-bit rule
does not promise this readback across all processors; physical Pentium III
behavior remains unverified. Evidence: `artifacts/native-fpu-control/results.json`.

## Status gaps and C1

Map SoftFloat invalid/infinite/overflow/underflow/inexact flags to x87
IE/ZE/OE/UE/PE explicitly; their bit positions differ. Clear temporary flags per
operation and merge supported exceptions into guest sticky state. The `8086`
specialization defaults to tininess after rounding. DE (denormal operand),
stack/tag faults, pending unmasked exceptions, and SEH delivery remain wrapper
responsibilities. Keep unsupported cases diagnostic rather than treating them
as successful arithmetic.
[API flags](https://raw.githubusercontent.com/ucb-bar/berkeley-softfloat-3/a0c6494cdc11865811dec815d5c0049fba9d82a8/source/include/softfloat.h),
[8086 specialization](https://raw.githubusercontent.com/ucb-bar/berkeley-softfloat-3/a0c6494cdc11865811dec815d5c0049fba9d82a8/source/8086/specialize.h)

SoftFloat exposes no C1 rounding indicator. Intel describes C1 in terms of
significand rounding versus truncation, not simply numerical movement toward
positive infinity. A possible finite-result bridge is to recompute an inexact
operation at the same precision using `round_minMag`, compare canonical result
magnitudes, then restore the requested result/mode/flags. **This comparison is
an inference, not implemented or tested.** Initially exclude overflow,
underflow, noncanonical values, and unmasked exception handling from that claim.
[Intel SDM sections 8.5.4–8.5.6](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366521.pdf)

A later single-pass hook could report the final significand increment from
[`source/s_roundPackToExtF80.c`](https://raw.githubusercontent.com/ucb-bar/berkeley-softfloat-3/a0c6494cdc11865811dec815d5c0049fba9d82a8/source/s_roundPackToExtF80.c).
Its `doIncrement` alone is insufficient: nearest-even correction may undo the
increment. Overriding `softfloat_raiseFlags` also cannot supply C1; ordinary
inexact handling can update flags directly.

## Next validation task

Build an isolated Wasm arithmetic harness with this pin before integration.
Compare raw 80-bit outputs, C1, exception flags, control state, and unchanged
operands against an authored native x87 fixture. Cover add/subtract/multiply/
divide, both signs, all 3 supported precision settings and 4 rounding modes,
halfway even/odd cases, cancellation, signed zero, and memory-operand conversion.
Check exceptional boundaries separately before enabling them. Preserve explicit
oracle discrepancies; do not use an interpreter result as unquestioned hardware
truth. Only then migrate guest storage/transactions and integrate required
instructions incrementally. No original native game execution is required.
