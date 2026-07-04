# ZIT Implementation Audit Report

**Date:** 2026-07-04 · **Branch:** `main` @ `8065b43` · **Test suite:** 91/91 passing (`zig build test`)

ZIT is a DEX (Dalvik bytecode) → x86-64 JIT compiler written in Zig, targeting Windows x64.
Pipeline: `DEX parse → decode → CFG → SSA construction → optimize → de-SSA → lower → regalloc → emit → execute`.

---

## 1. Verified End-to-End Behavior

Live JIT runs against `jit/classes.dex` (compiled from `samples/Main.java`):

| Method | Result | Status |
|---|---|---|
| `sum(10)` | 55 | ✅ correct |
| `factorial(5)` | 120 | ✅ correct |
| `fib(10)` (iterative, long) | 55 | ✅ correct |
| `floatDivComplex(6.0, 2.0)` | 16 | ✅ correct (float SSE path works) |
| `fibRecursive(10)` | `error.UnsupportedInstruction` | ❌ **fails — no `call` encoding in emitter** |

The most recent commit added `fibRecursive` for benchmarking, but recursive methods cannot currently be JIT-executed: `invoke` lowers to a `call` machine instruction that the emitter has no encoding for.

---

## 2. Module-by-Module Completion Status

### 2.1 `dex/parser.zig` (~99 KB, 18 tests) — **~85% complete, mature**
- Parses header, string pool (MUTF-8), types, protos, fields, methods, class defs, code items; decodes the full Dalvik opcode set with proper widths; Kotlin `@Metadata` annotation extraction.
- Good defensive error handling (`FileTooSmall`, `InvalidMagic`, `TruncatedInstruction`, `BadBranchTarget`, index bounds checks).
- **Missing:** try/catch exception tables (`tries`/`handlers`), debug_info items, general annotation parsing (only Kotlin metadata is handled).

### 2.2 `inst/instructions.zig` + `dex/print.zig` — **complete for scope**
- Instruction union covering the Dalvik ISA plus a disassembly printer. Low risk.

### 2.3 `jit/cfg.zig` (~46 KB, 15 tests + integration test) — **~90% complete, solid**
- Basic-block splitting, successors/predecessors, dominators, dominator tree, dominance frontiers, phi insertion, SSA variable renaming.
- Validates branch targets (`BadBranchTarget`); good test coverage including a real d8-produced DEX integration test.
- **Missing:** exception-edge modeling (no try/catch → no exceptional control flow in the CFG).

### 2.4 `jit/ir.zig` (3 tests) — **~70% complete**
- Clean SSA 3-address IR with pretty-printing.
- **Missing opcodes** (root cause of translator hacks below): `neg`/`not`, all type conversions, `cmp_long`/`cmpl`/`cmpg`, `rem_long`, long logical/shift ops, `rem_float`/`rem_double`, `array_length`, `instance_of`, `check_cast`.

### 2.5 `jit/translate.zig` (10 tests) — **~55% complete — biggest correctness risk**
Every Dalvik opcode is *accepted*, but many are translated to **semantically wrong placeholders that silently miscompile**:

| Dalvik opcode(s) | Translated as | Correct? |
|---|---|---|
| `neg_int/not_int/neg_long/…` + all 15 conversions (`int_to_byte`, `long_to_int`, …) | plain `move` | ❌ |
| `rem_long, and_long, or_long, xor_long, shl_long, shr_long, ushr_long` | `add_long` | ❌ |
| `rem_float` / `rem_double` | `div_float` / `div_wide` | ❌ |
| `cmp_long, cmpl/cmpg_float/double` | `sub_int` | ⚠️ approximation (wrong NaN/ordering semantics) |
| `instance_of` | `const 1` (always true) | ❌ |
| `check_cast` | no-op move | ⚠️ (no type check) |
| `array_length` | `move` of array ref | ❌ |
| `invoke` | `method_idx` hardcoded to **0**, no method resolution | ❌ |
| `move_exception`, `filled_new_array` | placeholder moves | ❌ |
| `monitor_enter/exit`, `fill_array_data` | dropped | ⚠️ |
- `move_result` fusion into preceding `invoke` works correctly.
- **These fail silently — a wrong result, not an error.** This is the most dangerous property of the current codebase.

### 2.6 `jit/opt.zig` (~130 KB, 12 tests) — **~75% complete, ambitious**
Fixed-point driver (≤10 iterations) running: simplifyCFG (dead-branch folding, unreachable-block pruning, block merging), value-range propagation, loop strength reduction, loop unrolling, LICM, GVN, copy-prop + constant folding, global register coalescing, dead-code elimination.
- Real, tested implementations for the classic scalar/loop passes.
- **`devirtualizeAndInline` is a mock:** hardcoded magic `method_idx >= 100` / `== 100/101` getter-setter demo logic. Since the translator always emits `method_idx = 0`, it never fires on real code — but it would misbehave the moment real method indices flow through.
- No pass-ordering diagnostics or IR verification between passes.

### 2.7 `jit/dessa.zig` (6 tests) — **~90% complete**
- Phi elimination with parallel-copy resolution (handles swap/cycle cases via temporaries) and post-SSA copy propagation. Sound approach, well tested.

### 2.8 `jit/lower.zig` (11 tests) — **~80% complete**
- Lowers all IR ops to virtual x86 (int/float ALU, idiv/irem pattern, `mul_long`/`div_long` special-cased, SIB addressing for arrays, dead-mov peephole).
- Runtime-dependent ops (`new_instance`, `iget/iput`, `invoke`, `switch`, `throw`) lower to **stub machine instructions with no backing implementation**.
- **Bug:** `aget/aput` hardcode element scale = 4 and header disp = 16 — wrong for `wide` (8-byte), `byte/boolean` (1), `char/short` (2) arrays.

### 2.9 `jit/regalloc.zig` (~53 KB, 4 tests) — **~85% complete**
- Linear-scan over live intervals, separate GPR/XMM classes, loop-aware liveness, Windows x64 convention (RCX/RDX/R8/R9 + XMM0-3, stack params for 5+ args), callee-saved preference for values live across calls, spill-to-stack with furthest-end victim selection.
- **Issue:** leftover `std.debug.print` interval dumps pollute stderr on every compile.
- Spilled operands may still hit `UnsupportedOperandCombination` in the emitter (no load/store splitting of memory-memory ops).

### 2.10 `jit/emitter.zig` (~40 KB, 2 tests) — **~50% complete — the pipeline bottleneck**
Encodes: `mov` (reg/imm/imm64/mem/stack), `add`, `sub`, `imul`, `neg`, SSE `add/sub/mul/div/mov` (ss+sd), `xor`, `cmp`, `jmp/je/jne/jl/jge/jg` with rel32 relocation patching, full prologue/epilogue (RBP frame, callee-saved GPR push/pop, XMM save/restore), return-value marshalling.
**No encoding for** (→ `UnsupportedInstruction` at emit time):
- `idiv` / `irem` — **any method using div/rem fails**
- `and` / `or`, `shl` / `shr` / `ushr` — bitwise/shift methods fail
- `test` + `jz` / `jnz` — `if_eqz`/`if_nez` branches fail
- `jle` — `if_le` fails
- `call` — **no method invocation at all** (confirmed: `fibRecursive` fails)
- all runtime stubs: `alloc_obj`, `alloc_arr`, `field_load/store`, `switch_stub`, `throw_stub`

### 2.11 `jit/exec_mem.zig` (2 tests) — **complete for scope, security concern**
- `VirtualAlloc`/`VirtualFree` wrappers; two genuine end-to-end "execute on real CPU" tests.
- **Uses `PAGE_EXECUTE_READWRITE` (W^X violation)** — should allocate RW, copy, then `VirtualProtect` to RX. Windows-only (no cross-platform abstraction).

### 2.12 `src/dex_dbg.zig` (~35 KB) — **functional dev driver, rough**
- Rich CLI: `info/classes/methods/fields/types/strings/disasm/cfg/emit/ssa/ssa-opt/dessa/lower/codegen/run/kotlin`.
- SSA def-map construction and phi-insertion orchestration live *here* rather than in a library module — the JIT pipeline cannot currently be invoked as a library.
- `run` harness hardcodes exactly 4 parameters and one i64/f32/f64 shape; ad-hoc signature parser; `parseInt … catch 0` swallows bad input; debug prints to stderr.

### 2.13 `src/main.zig` / `src/root.zig` — **0% (untouched Zig template)**
- Still `zig init` boilerplate ("All your codebase are belong to us"). The real entry point is `dex-dbg`.

### 2.14 `nanopb/` + Kotlin metadata — **working sideline**
- Minimal nanopb-based protobuf decoding of Kotlin `@Metadata` (d1/d2), with MUTF-8 and 8-to-7-bit unpacking. Orthogonal to the JIT.

---

## 3. Completion Summary

| Module | Completion | Tests | Risk |
|---|---|---|---|
| dex/parser | ~85% | 18 | Low |
| inst + print | ~95% | 1 | Low |
| jit/cfg | ~90% | 15+4 | Low |
| jit/ir | ~70% | 3 | Medium (missing opcodes) |
| jit/translate | ~55% | 10 | **High (silent miscompiles)** |
| jit/opt | ~75% | 12 | Medium (mock inliner) |
| jit/dessa | ~90% | 6 | Low |
| jit/lower | ~80% | 11 | Medium (array scale bug) |
| jit/regalloc | ~85% | 4 | Medium (debug noise, spill combos) |
| jit/emitter | ~50% | 2 | **High (pipeline bottleneck)** |
| jit/exec_mem | ~90% | 2 | Medium (RWX pages) |
| src/dex_dbg | ~70% | — | Low (dev tool) |
| src/main | 0% | — | — |

**Overall: a straight-line int/float arithmetic method with loops and simple comparisons JIT-compiles and runs correctly. Anything involving calls, division, bitwise ops, zero-comparisons, objects, arrays, strings, switches, or exceptions cannot execute yet.**

---

## 4. Robustness Findings (priority order)

1. **Silent miscompilation in the translator** — placeholder translations (§2.5) produce wrong *values*, not errors. Replace each with either a correct IR op or a hard `error.UnimplementedOpcode` so failures are loud.
2. **Late failure detection** — unsupported ops surface only in the emitter, after the whole pipeline has run. A capability check at translate time would reject unsupported methods up front.
3. **RWX executable memory** — switch to W^X (`VirtualProtect` RW→RX flip) in `exec_mem.zig`.
4. **No exception support end-to-end** — parser skips try/catch tables, CFG has no exceptional edges, `throw` is a stub. Fine for now, but document it as a hard boundary.
5. **`unreachable` on data-dependent paths** — e.g. `translate.zig:27` branch-target resolution trusts the CFG builder; a mismatch is instant UB in release builds. Prefer returned errors.
6. **Debug noise** — `std.debug.print` left in regalloc (and driver signature dump); pollutes every compile including passing test runs.
7. **Driver fragility** — hardcoded 4-arg call shapes, `catch 0` on argument parsing, ad-hoc signature scanner duplicated logic.
8. **Uncommitted binary change** — `jit/classes.dex` is modified in the working tree; committing binaries into `jit/` (a source dir) is fragile — consider a build step regenerating it from `samples/`.

---

## 5. Optimization / Improvement Areas

**Compiler output quality**
- Emitter completeness is worth more than any new optimizer pass right now: `call`, `idiv/irem`, shifts, bitwise, `test/jz/jnz/jle` unlock most real methods.
- `switch_op` lowering is a stub; jump-table emission would complete control flow.
- Register allocator: second-chance binpacking or use-position splitting would reduce spills; currently no spill-slot reuse (`next_stack_offset` only grows).
- Block layout: no fallthrough optimization — every block ends in an explicit `jmp` even to the next block (relocation always emitted).

**Optimizer**
- Replace the mock `devirtualizeAndInline` with real method resolution once `method_idx` is plumbed through from the parser.
- Add an IR verifier run between passes in debug builds (SSA dominance, phi arg/pred consistency) — cheap insurance for a 130 KB pass file.
- The 10-iteration fixed-point cap is arbitrary; convergence is usually 2-3, but a changed-work-list would be cleaner.

**Architecture**
- Extract the SSA-construction orchestration (def-map + phi insertion, `dex_dbg.zig:547-644`) into a `jit/ssa.zig` library entry point `compileMethod()` so the JIT is usable outside the CLI.
- Type inference pass: the IR is untyped (int/long/float distinguished only by opcode), which is why array scale and conversions are broken. A per-SSA-var type table would fix `aget/aput` widths and enable correct conversions.
- Runtime layer: `alloc_obj`/`field_load`/`call` stubs need a minimal runtime (object model, method table, allocation) before object-oriented code can run.

---

## 6. Suggested Next Steps (smallest work → biggest unlock)

1. Emit `test/jz/jnz/jle`, `and/or`, shifts, `idiv/irem` (encodings are mechanical) — unlocks most arithmetic methods.
2. Emit `call` with a method-address resolution table — unlocks `fibRecursive`, the stated benchmark goal.
3. Fix wrong translator placeholders (at minimum `neg`, conversions, long logical ops) or make them hard errors.
4. Silence debug prints; flip exec memory to W^X.
5. Plumb real `method_idx` from parser → translate → invoke.
