  Status legend: [x] done  [~] partial  [ ] todo
  Status checked against current code on 2026-02-12.

  Phase 1: Critical Fixes [x]

  1.1 Limit Warnings (src/loader.rs, src/compiler/ir_to_mir.rs)
  - Added constants MAX_STRING_SIZE (128) and MAX_MAP_ENTRIES (10240)
  - Added runtime warnings when maps exceed 80% capacity
  - Added compile-time warnings when strings or read-str max-len exceed 128 bytes

  1.2 README Update (README.md)
  - Complete rewrite with proper documentation
  - Installation guide, capability setup, quick start examples
  - Context fields table, command reference, limits documentation

  1.3 Integration Tests (tests/integration.rs)
  - 17 new integration tests covering:
    - Probe specification parsing (kprobe, tracepoint, uprobe, uretprobe, raw_tracepoint)
    - UprobeTarget parsing (function, offset, PID combinations)
    - EbpfState creation and error handling
    - Invalid input handling

  Phase 2: Code Quality Cleanup [x]

  2.1 Dead Code Removal (src/compiler/ir_to_mir.rs)
  - Removed 200-line SubfunctionLowering struct and impl block
  - Added note pointing to git history for future reference
  - Annotated reserved fields with #[allow(dead_code)]

  2.2 Mutex Error Handling (src/loader.rs, src/commands/list.rs)
  - Added LockPoisoned variant to LoadError enum
  - Replaced 11 .lock().unwrap() calls with proper error handling
  - Updated list() to return Result<Vec<ProbeInfo>, LoadError>
  - Updated caller in commands/list.rs

  Phase 3: Documentation Improvements [x]

  Concrete plan (phased, with deliverables)

  [x] 1. Define the "Verifier-Compatible Core" (VCC) IR
      - Create a minimal typed core language that explicitly encodes all pointer-sensitive ops and helper calls, with rules
        that mirror verifier expectations (e.g., pointer + pointer becomes invalid). (docs.kernel.org (https://
        docs.kernel.org/bpf/verifier.html?utm_source=openai))
      - This becomes the stable boundary: everything above lowers into VCC; everything below must preserve its invariants.
      Status: VCC is a mandatory compile gate; pointer arithmetic + size-aware stack bounds enforced; string/record ops,
      map/ringbuf ops, and strcmp now modeled. (Generic CallHelper remains opaque.)

  [x] 2. Introduce a 3-tier IR pipeline
      - HIR: high-level AST with HM-style type inference and let-generalization for rank-1 polymorphism. (research.ed.ac.uk
        (https://www.research.ed.ac.uk/en/publications/a-theory-of-type-polymorphism-in-programming?utm_source=openai))
      - MIR (SSA): explicit control flow + SSA values to make dataflow and types compositional. (cs.brown.edu (https://
        cs.brown.edu/research/pubs/techreports/reports/CS-91-21.html?utm_source=openai))
      - LIR: low-level, explicit temporaries, explicit call/return, explicit loads/stores. No hidden scratch registers.
      Status: HIR now normalizes literals and instruction string fields (removes DataSlice
      coupling) and preserves IR metadata; MIR lowering consumes HIR directly (IR → HIR → MIR
      wrapper retained for compatibility). LIR introduced with a checked MIR→LIR pass and the
      pipeline now compiles LIR directly.

  [x] 3. Make the register file a first-class object
      - Encode the eBPF ABI in the compiler: R0 return, R1-R5 args (caller-saved), R6-R9 callee-saved, R10 frame pointer.
        (kernel.org (https://www.kernel.org/doc/html/v5.19/bpf/instruction-set.html?utm_source=openai))
      - All scratch usage must be represented as LIR temporaries so the allocator can reason about interference (this resolves
        the current "implicit clobber" bug class).
      - Implement parallel move lowering for arguments/returns in LIR so cycles are correct by construction (no ad-hoc swaps).
      - Ensure parallel-move lowering handles cases where R0 is part of the move set (avoid reliance on R0 as the temp).
      Status: LIR introduced; MIR→LIR pass creates precolored ABI vregs (R0–R5) and explicit
      CallSubfn/CallHelper arg shuffles; allocator now consumes LIR and enforces call/scratch
      clobbers from LIR metadata; codegen consumes LIR and lowers ParallelMove deterministically
      (cycle-safe) with a temp stack slot, including R0-involved cycles. MIR→LIR now rejects
      helper/subfunction calls beyond the ABI limit (5 args) and subfunctions beyond 5 params.

  [x] 4. Rebuild type inference as a two-layer system
      - Layer A (HM): rank-1 polymorphism with algorithm W; principal types for predictable inference and error messages.
        (research.ed.ac.uk (https://www.research.ed.ac.uk/en/publications/a-theory-of-type-polymorphism-in-programming?
        utm_source=openai))
      - Layer B (Verifier types): flow-sensitive abstract types for register/stack values (PTR_TO_CTX, PTR_TO_MAP_VALUE,
        SCALAR, etc.), modeled as an abstract interpreter over MIR/LIR. (docs.kernel.org (https://docs.kernel.org/bpf/
        verifier.html?utm_source=openai))
      - Integration rule: HIR types must lower into MIR with verifier-type obligations, then the abstract interpreter
        discharges them (or produces an error).
      Status: HM-style constraint inference exists at MIR; HIR inference now emits type hints that
      lower into MIR and constrain MIR inference for verifier/VCC; verifier-type layer now implemented
      for MIR with flow-sensitive pointer/nullability tracking (map lookup requires null check) and
      integrated into the compile pipeline before VCC.

  [x] 5. Polymorphism strategy (powerful but principled)
      - Rank-1 parametric polymorphism: fully inferred (HM). (research.ed.ac.uk (https://www.research.ed.ac.uk/en/
        publications/a-theory-of-type-polymorphism-in-programming?utm_source=openai))
      - Polymorphic recursion: require explicit type annotations; inference is known to be much harder and studied as a
        separate problem. (researchprofiles.ku.dk (https://researchprofiles.ku.dk/en/publications/type-inference-with-
        polymorphic-recursion?utm_source=openai))
      - Impredicative or partial polymorphic inference: require explicit type applications/annotations; full inference is
        undecidable. (research.google (https://research.google/pubs/partial-polymorphic-type-inference-is-undecidable/?
        utm_source=openai))
      Status: HIR let-generalization now implemented for Store/LoadVariable using HM-style schemes, and
      HIR inference runs after IR→HIR lowering (before HIR→MIR) to support rank-1 polymorphism.
      HIR inference now constrains list/record/string ops and range literals to reduce Unknown propagation.
      Recursive subfunction polymorphism is rejected with explicit guidance that polymorphic recursion
      requires annotations and is not currently supported.

  [x] 6. Verifier-aligned abstract interpretation pass
      - Implement a small interpreter that tracks register types, stack slots, and ranges, following the kernel's model
        (PTR_TO_CTX, PTR_TO_MAP_VALUE, SCALAR_VALUE, NOT_INIT). (docs.kernel.org (https://docs.kernel.org/bpf/verifier.html?
        utm_source=openai))
      - This becomes a compile-time "pre-verifier": it should reject anything the kernel verifier would reject, and ideally
        catch more with better error messages.
      Status: verifier-type pass now enforces pointer space/nullability for loads/stores, read-str helpers,
      list ops, and record/emit string pointers, plus stack-slot and map-value bounds on load/store and
      stack/map pointers. Scalar range tracking now propagates through consts, add/sub/mul/div/mod/shift,
      non-zero guards, compare guards (eq/ne/lt/le/gt/ge vs constants and vregs), bitwise ops (bounded non-negative,
      mask-derived; exact for constants), and phi joins, preserving bounds across non-constant offsets and
      pointer phis. Comparison-based range refinement now narrows branch ranges and preserves non-zero info.
      Branch feasibility pruning now drops contradictory compare branches, and bounded `!= const`
      fact sets are tracked per vreg to reject impossible follow-up `== const` branches.
      Bounded stack range analysis exists in MIR type inference; VCC verifier is now
      integrated as a compile-time gate; full model not implemented.

  [x] 7. Register allocation & codegen modernization
      - Use graph coloring with spill cost heuristics on LIR (post-SSA destruction), with explicit precolored regs and
        clobbers. (research.ibm.com (https://research.ibm.com/publications/register-allocation-andamp-spilling-via-graph-
        coloring--1?utm_source=openai))
      - Ensure every helper call (and subprogram call) has explicit clobber constraints; no "secret" register usage.
      - Plumb loop depth into LIR spill-cost heuristics (carry LoopInfo through LIR or recompute on LIR CFG).
      Status: graph coloring allocator exists with spill costs; allocator now consumes LIR and
      uses LIR clobbers; loop-depth heuristics now computed for LIR via alloc CFG. Worklist/adjacency
      processing is deterministic with stable tie-breaking for freeze/spill selection. Call-clobber
      constraints are covered with helper/subfunction live-across-call allocator tests.

  [x] 8. Testing strategy aligned with the design
      - Unit tests for HM inference and principal type schemes.
      - "Verifier-style" tests: run the abstract interpreter against negative examples (pointer + pointer, illegal stack
        access, etc.). (docs.kernel.org (https://docs.kernel.org/bpf/verifier.html?utm_source=openai))
      - Golden tests for register allocation stability (no unintended clobbers, correct spills).
      Status: HM + regalloc tests exist; initial verifier-style tests added in VCC module; regalloc now has
      repeated-allocation stability tests and MIR→eBPF has repeated-compilation bytecode stability coverage.

  What this buys us

  - A compiler that is predictably safe (verifier-aligned), expressive (HM + explicit polymorphism), and architecturally
    scalable (SSA + LIR + explicit ABI).
  - It eliminates the current hidden-scratch-reg hazard at the root, instead of treating it symptomatically.

  Notes (2026-01-25)
  - Implemented bounded stack slice/range analysis in type_infer to allow dynamic stack offsets when bounded.
  - Implemented list lowering with explicit bounds checks to keep stack pointer arithmetic verifier-safe.
  - Added initial VCC IR scaffolding and verifier checks for pointer arithmetic and stack bounds.
  - Wired VCC verification into the compile pipeline as a mandatory pre-codegen gate.
  - String buffers now track length vregs and grow to fit interpolation; literal length updates ignore padding.
  - Integer string append codegen no longer uses stack-pointer subtraction; fixed loop skip offset.
  - VCC now checks map/ringbuf/strcmp pointer use and size-aware bounds; ctx.comm uses an explicit stack slot.
  - Added HIR container + hir_to_mir seam; attach now goes through IR → HIR → MIR.
  - HIR now normalizes literals and instruction string slices (owned bytes) while preserving
    spans/ast/comments.
  - HIR instruction coverage expanded (Raw removed) and MIR lowering now consumes HIR directly.
  - HIR→MIR no longer pre-allocates a placeholder entry block (fixes VCC placeholder terminator failures).
  - Count map lowering updated to MapRef/MapKind; LoadCtxField now threads optional comm stack slot.

  Verifier notes (2026-02-12)
  - Branch feasibility pruning for contradictory compare guards is now implemented.
  - `!= const` facts are now tracked across branches and used to prune contradictory `== const` follow-up guards.
  - Multiple excluded constants are preserved per vreg (bounded fact set) so chained `!=` guards retain precision.

  Notes (2026-01-28)
  - User-defined function calls now lower to BPF subfunctions via `view ir --json --decl-id`,
    with HIR type hints threaded into subfunction MIR and per-subfunction hints returned to the verifier.
  - Attach now scans main/closure IR for DeclIds, fetches nested user IR + closure IR, and wires HIR→MIR with decls.
  - ELF generation now emits subfunction symbols and main-function size for aya relocation; StoreVariable/DropVariable
    now track local bindings to support $in pipelines in user-defined functions.
  - User function signatures are pulled from `scope commands` to allow unused params and named args/flags.
