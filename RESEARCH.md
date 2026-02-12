  1. SSA Construction: Cytron (1991) — Appropriate, but consider the maintenance cost

  Your approach: Separate-pass SSA construction via Cytron et al. with iterated dominance frontiers, implemented in
  passes/ssa.rs.

  Assessment: This is the right algorithm for your architecture. Since MIR is fully constructed before SSA runs, Braun et al.
  (2013) on-the-fly construction would only make sense if you restructured hir_to_mir.rs to build SSA form during lowering. For
  eBPF-sized programs (under ~500 vregs), the performance difference is immaterial.

  The real problem is rename_uses() (passes/ssa.rs:301-500). This function manually reconstructs every single MirInst variant —
  all 30+ of them — to replace VReg uses with their SSA-renamed versions. This is the quintessential "fragile visitor" pattern.
  Every time a new MirInst variant is added, this function must be updated in lockstep, and the compiler won't warn you if you
  miss one (the match has no wildcard fallthrough that would cause a compile error — but it also wouldn't catch a new variant
  returning the old unrenamed instruction).

  Recommendation: Consider adding a generic map_uses or transform_values method on MirInst that takes closures for value/vreg
  transformation. This would centralize the "walk all operands" logic and make SSA renaming, copy propagation, and other
  per-operand transforms all use the same visitor. The uses() and defs() methods on LirInst already catalog operands — extending
   this pattern to MirInst with mutation support would eliminate the fragility. Something like:

  impl MirInst {
      fn map_uses(&mut self, f: impl Fn(VReg) -> VReg, fv: impl Fn(&MirValue) -> MirValue) { ... }
  }

  This is an infrastructure concern, not a theoretical one — as you add more domain-specific instructions (you already have
  ~30), the combinatorial cost of maintaining separate operand-walking code in SSA rename, copy prop, DCE, liveness, etc. will
  compound.

    ---
  2. SSA Destruction: Naive — Potential correctness issue

  Your approach: ssa_destruct.rs inserts dst = src_i copies at the end of each predecessor for every phi argument, then removes
  the phis.

  The problem: This is acknowledged as "naive" in the source comments, with the claim that "critical edges are handled by the
  register allocator through spilling." That claim deserves scrutiny.

  Consider this loop pattern:
  bb_header: v1 = phi(v0:bb_entry, v2:bb_body)
  bb_body:   v2 = f(v1)
             jump bb_header

  Naive destruction inserts v1 = v2 at the end of bb_body. But v2 is defined in terms of the old v1. If v1 and v2 interfere
  (they do — v1 is live across the definition of v2), the copy v1 = v2 at the end of bb_body is sequentially correct (it happens
   after v2 = f(v1), so v1 has already been consumed). But consider multiple phis at the same join point:

  bb3: a = phi(x:bb1, c:bb2)
  bb3: b = phi(y:bb1, a:bb2)

  From bb2, you need a = c; b = a — but the second copy reads a, which was just overwritten. This is the classic lost copy
  problem (Briggs et al. 1998). Your phi arguments happen to be iterated in definition order, and the copies are appended
  sequentially, meaning later phis' sources can be clobbered by earlier phis' copies in the same predecessor.

  Real-world risk: For the simple diamond CFGs that dominate your current Nushell-to-eBPF compilation, you likely haven't hit
  this. But any loop with multiple live variables updated in the body will generate multiple phis at the header, and the
  ordering becomes safety-critical.

  Recommendation: Implement Boissinot et al. (2009) parallel copy sequentialization. The algorithm is straightforward:
  1. Collect all phi copies per predecessor as a parallel copy set {(dst_i, src_i)}.
  2. Topologically sort the copies, breaking cycles with a temporary register.
  3. Emit the copies in the computed order.

  This is a localized fix — ~50-80 lines of code replacing the current insert_copy loop — and eliminates the correctness risk
  entirely.

    ---
  3. Constant Folding: Per-block only — SCCP would be strictly better

  Your approach: const_fold.rs walks blocks linearly, maintaining a HashMap<VReg, i64> that resets between blocks.

  What you miss: Inter-block constant propagation through phis. Example:

  bb1: v = 5; jump bb3
  bb2: v = 5; jump bb3
  bb3: v_phi = phi(v:bb1, v:bb2)
       use v_phi  // v_phi is always 5, but your folder doesn't know

  Also, SCCP (Sparse Conditional Constant Propagation, Wegman & Zadeck 1991) combines constant propagation with reachability
  analysis. It can determine that when a branch condition is known constant, the untaken successor is unreachable, preventing
  constants from that dead path from polluting the analysis. Your current approach runs constant folding, then branch
  optimization, then DCE as separate passes that must iterate to converge. SCCP does all three simultaneously in a single pass
  with two worklists (SSA edges and CFG edges).

  Practical impact: For typical eBPF programs compiled from Nushell, this likely matters less than for a general-purpose
  compiler. But since you already have SSA form when the pass runs, SCCP would be a drop-in replacement that is both more
  powerful and potentially faster (no need for fixed-point iteration across multiple separate passes for the
  constant/reachability component).

  Priority: Medium. This is an optimization quality improvement, not a correctness issue.

  ---
  4. Register Allocation: Graph Coloring — Excellent choice, well-implemented

  Your approach: Chaitin-Briggs with IRC in graph_coloring.rs, operating on LIR after SSA destruction.

  Assessment: This is the best choice for eBPF's 4 callee-saved registers (R6-R9). With so few registers, allocation quality
  directly determines whether programs fit in the 512-byte stack limit. Graph coloring gives optimal or near-optimal results for
   small interference graphs.

  Specific things done well:
  - Loop-depth-weighted spill costs (10^depth) — correctly prioritizes keeping loop-hot values in registers
  - Briggs and George coalescing criteria — conservative coalescing that never increases spill pressure
  - Spill slot reuse via interference coloring — critical for the 512-byte stack constraint
  - Forbidden register sets for clobbers — correctly models R1-R5 caller-saved and per-instruction scratch clobbers

  One enhancement worth considering: Rematerialization. When a spilled value is a constant load (v = 42) or a simple
  recomputable expression, you can re-emit the instruction at the use site instead of spilling to the stack. This saves both a
  store and a load instruction and avoids consuming stack space for the spill slot. For eBPF where both instructions and stack
  bytes are precious, this is high-value.

  The generic trait design (RegAllocInst/RegAllocBlock/RegAllocFunction) is well-engineered — it keeps the allocator independent
   of the IR representation.

  ---
  5. Duplicated Analysis Infrastructure

  graph_coloring.rs reimplements AllocCfg, AllocLiveness, compute_idom, and compute_loop_depths (~250 lines) that substantially
  overlap with cfg.rs's CFG, LivenessInfo, CFG::compute_dominance, and LoopInfo.

  The generic trait design in graph_coloring.rs is the reason — the allocator operates over RegAllocFunction which abstracts
  over both MIR and LIR, while cfg.rs is MIR-specific. This is a legitimate design tension.

  However: The dominator computation (compute_idom in graph_coloring.rs) is a separate implementation of the same
  Cooper-Harvey-Kennedy algorithm that cfg.rs uses. The liveness computation follows the same backward dataflow pattern. Having
  two implementations means two places for bugs.

  Recommendation: Consider making CFG generic over a block/instruction trait (similar to how graph_coloring already uses
  traits), or extracting the algorithms into shared functions parameterized by accessor closures. This is a maintainability
  concern — the duplicated code works correctly today, but two copies of dominator computation and liveness analysis is a
  liability.

  ---
  6. Block Lookup: O(n) Linear Search

  MirFunction::block() and block_mut() (mir.rs:800-813) iterate through all blocks to find one by ID. Same pattern in
  LirFunction (lir.rs:128-140). This is called pervasively throughout the compiler.

  For eBPF-sized programs (tens of blocks), the performance impact is negligible. But it's an unusual design choice — most
  compilers use either indexed Vec (where BlockId is the index) or HashMap. Your BlockId is already BlockId(u32) which is the
  block's index at allocation time, and alloc_block appends to the Vec, so in practice block.id.0 == index — unless blocks are
  reordered or removed.

  Recommendation: If block IDs always correspond to Vec indices (which appears to be the case — I don't see any block
  reordering), you could replace the linear search with &self.blocks[id.0 as usize] with a debug assert. If blocks can be
  removed (creating holes), use an Option<BasicBlock> slot or a secondary index. This is a minor cleanup, not urgent.

    ---
  7. PassManager: CFG Invalidation Strategy

  Your approach: PassManager::run() rebuilds the CFG once at the start of each iteration, then runs all passes with that same
  CFG.

  The subtle issue: If pass A modifies the CFG structure (e.g., branch optimization removes a block or redirects an edge),
  passes B through E in the same iteration see a stale CFG. The MirPass::run signature passes &CFG, implying the pass should
  treat it as read-only ground truth — but the function is &mut MirFunction, so the pass can freely invalidate the CFG.

  In practice: Your current passes handle this gracefully:
  - ConstantFolding modifies instruction content but not CFG structure (folded branches become jumps, but the blocks still
  exist)
  - BranchOptimization modifies edges but not block structure
  - DCE removes unreachable blocks (which do invalidate the CFG)

  The fixed-point iteration (max 10) compensates — stale CFG effects are corrected on the next iteration's rebuild. But this is
  a design smell. The standard approach is either:
  1. Invalidation flags: Passes declare what analyses they invalidate; the manager recomputes on demand
  2. Pass-local rebuild: Each pass that needs fresh analysis recomputes it internally

  Your current approach works because of the small program sizes and iterative convergence, but it's worth noting in
  documentation that pass ordering has implicit CFG freshness dependencies.

  ---
  8. VCC (Verifier-Compatible Core): Sophisticated and well-designed

  Your approach: Separate IR with abstract interpretation, tracking pointer provenance, nullability, scalar ranges, and ringbuf
  lifetimes. Worklist-based forward analysis with state merging at join points. Branch refinement for null checks and scalar
  comparisons.

  Assessment: This is the most architecturally interesting part of the compiler. Building a pre-verifier that mirrors the
  kernel's verifier.c abstract interpretation is the right approach for a non-LLVM eBPF compiler. Specific strengths:

  - Pointer provenance tracking via AddressSpace (Stack, MapValue, Context, RingBuf, Kernel, User) — mirrors the kernel
  verifier's bpf_reg_state type tracking
  - Nullability refinement through branches — essential for map lookup patterns (ptr = map_lookup(); if (ptr != NULL) { ... })
  - Ringbuf lifetime tracking — catching submit-before-reserve and use-after-submit
  - Bounded iteration (MAX_STATE_UPDATES_PER_BLOCK = 64) — pragmatic convergence guarantee

  Potential improvement: Widening strategy. Your bounded iteration count acts as a blunt widening. For loops, a more precise
  approach:
  1. Apply standard widening only at loop headers (blocks that are targets of back edges)
  2. After reaching a widened fixed point, optionally run narrowing iterations to recover precision lost during widening
  3. For scalar ranges specifically: widen [lo, hi] to [-inf, hi] or [lo, +inf] when bounds move outward across iterations

  This matters for programs with loops where the loop counter range affects pointer bounds calculations. Currently your bounded
  loops have explicit limit fields, so the verifier knows the range statically — but user-computed loop bounds could benefit
  from better range inference.

  Consider running VCC on SSA form. Currently VCC operates on a lowered IR. Running verification on SSA form would give you
  def-use chains for free, making the abstract interpretation sparse (only propagate when definitions change) rather than dense
  (re-analyze entire blocks). SSA form also makes phi placement explicit, which improves precision at join points — instead of
  merging all possible values, you merge exactly the values flowing from each predecessor.

    ---
  9. Type Inference: Dual HM is unusual but justified

  Your approach: Hindley-Milner type inference at both HIR level (hir_type_infer.rs with let-generalization) and MIR level
  (type_infer.rs with constraint-based unification).

  This dual-level inference is uncommon but makes sense for your pipeline. The HIR-level inference handles Nushell's dynamic
  typing to infer concrete types for eBPF compilation (e.g., figuring out that a pipeline produces integers). The MIR-level
  inference then validates and refines types in the register-level IR.

  The hindley_milner.rs implementation with TypeScheme, quantified variables, and proper instantiate/generalize is textbook
  correct. No concerns here.

  ---
  10. Multi-level IR Design: Clean separation, well-suited to the problem

  The four-level pipeline (HIR → MIR → LIR → eBPF) with VCC as a verification sidecar is well-architected:

  - HIR captures Nushell semantics (closures, blocks, captures)
  - MIR is the optimization target (SSA-capable, virtual registers, basic blocks)
  - LIR makes ABI constraints explicit (precolored registers, parallel moves)
  - VCC handles verification-specific concerns (pointer provenance, bounds)

  This is better suited to your problem than using LLVM IR (which would require fighting its general-purpose nature to express
  eBPF constraints) or MLIR (which would be over-engineered for a single-frontend single-backend compiler).

  The MIR→LIR boundary is particularly clean — the lowering in mir_to_lir.rs introduces explicit register precoloring and
  parallel moves for argument setup, giving the register allocator exactly the information it needs.

  ---
  Summary: Priority-ordered recommendations
  #: 1
  Issue: SSA destruction correctness (lost copy/swap problem)
  Severity: High — latent correctness bug
  Effort: Low (~80 lines for parallel copy sequentialization)
  ────────────────────────────────────────
  #: 2
  Issue: rename_uses() fragility — manual 200-line match that must track all MirInst variants
  Severity: Medium — maintenance hazard
  Effort: Medium (add map_uses/map_values to MirInst)
  ────────────────────────────────────────
  #: 3
  Issue: Duplicated dominator/liveness computation in graph_coloring.rs vs cfg.rs
  Severity: Medium — maintenance hazard
  Effort: Medium (extract shared algorithm)
  ────────────────────────────────────────
  #: 4
  Issue: Constant folding → SCCP upgrade
  Severity: Low-Medium — optimization quality
  Effort: Medium (~200 lines for SCCP on SSA)
  ────────────────────────────────────────
  #: 5
  Issue: Rematerialization in register allocator
  Severity: Low-Medium — stack pressure improvement
  Effort: Medium
  ────────────────────────────────────────
  #: 6
  Issue: VCC on SSA form
  Severity: Low — precision improvement
  Effort: High (restructure verification pipeline)
  ────────────────────────────────────────
  #: 7
  Issue: Block lookup O(n) → O(1)
  Severity: Low — performance
  Effort: Low
  ────────────────────────────────────────
  #: 8
  Issue: PassManager CFG invalidation
  Severity: Low — design cleanliness
  Effort: Low-Medium
  Items 1-3 are the ones I'd prioritize. Item 1 is a correctness risk that will bite as programs grow more complex. Items 2-3
  are infrastructure debt that compounds as the instruction set grows. The rest are genuine improvements but not urgent given
  the current program sizes and patterns your compiler handles.
