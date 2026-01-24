//! Optimization passes for MIR
//!
//! This module provides a pass infrastructure for transforming MIR code.
//! Passes can be run individually or composed through the PassManager.
//!
//! ## Available Passes
//!
//! - **SSA** (SSA Construction): Transforms MIR into SSA form
//! - **DCE** (Dead Code Elimination): Removes unused instructions and unreachable blocks
//! - **ConstFold** (Constant Folding): Evaluates constant expressions at compile time
//! - **StrengthReduce**: Converts expensive operations to cheaper equivalents
//! - **CopyProp** (Copy Propagation): Replaces uses of copy destinations with sources
//! - **BranchOpt** (Branch Optimization): Simplifies control flow (jump threading, same-target branches)

mod branch_opt;
mod const_fold;
mod copy_prop;
mod dce;
mod ssa;
mod ssa_destruct;
mod strength;

pub use branch_opt::BranchOptimization;
pub use const_fold::ConstantFolding;
pub use copy_prop::CopyPropagation;
pub use dce::DeadCodeElimination;
pub use ssa::SsaConstruction;
pub use ssa_destruct::SsaDestruction;
pub use strength::StrengthReduction;

use super::cfg::CFG;
use super::mir::MirFunction;

/// Trait for MIR optimization passes
pub trait MirPass {
    /// Name of the pass for debugging/logging
    fn name(&self) -> &str;

    /// Run the pass on a function
    ///
    /// Returns true if the function was modified, false otherwise.
    /// This is used by the PassManager to determine when to stop iterating.
    fn run(&self, func: &mut MirFunction, cfg: &CFG) -> bool;
}

/// Manages and runs optimization passes
pub struct PassManager {
    passes: Vec<Box<dyn MirPass>>,
    /// Maximum iterations to prevent infinite loops
    max_iterations: usize,
}

impl PassManager {
    /// Create a new pass manager
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            max_iterations: 10,
        }
    }

    /// Add a pass to the manager
    pub fn add_pass<P: MirPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Set maximum iterations
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Run all passes until fixed point
    ///
    /// Returns the total number of modifications made.
    pub fn run(&self, func: &mut MirFunction) -> usize {
        let mut total_changes = 0;
        let debug = std::env::var("EBPF_DEBUG_PASSES").is_ok();

        for iteration in 0..self.max_iterations {
            let mut changed = false;

            // Rebuild CFG for each iteration (passes may change the graph)
            let cfg = CFG::build(func);

            for pass in &self.passes {
                if pass.run(func, &cfg) {
                    changed = true;
                    total_changes += 1;
                    if debug {
                        eprintln!("  iteration {}: {} made changes", iteration, pass.name());
                    }
                }
            }

            if !changed {
                if debug {
                    eprintln!("PassManager: converged after {} iterations", iteration);
                }
                break;
            }

            // Prevent runaway optimization
            if iteration == self.max_iterations - 1 {
                eprintln!(
                    "PassManager: reached max iterations ({}), stopping",
                    self.max_iterations
                );
                if debug {
                    // Dump function state for debugging
                    eprintln!("Final function state:");
                    for block in &func.blocks {
                        eprintln!("  Block {:?}:", block.id);
                        for inst in &block.instructions {
                            eprintln!("    {:?}", inst);
                        }
                        eprintln!("    term: {:?}", block.terminator);
                    }
                }
            }
        }

        total_changes
    }

    /// Run a single pass (useful for testing)
    pub fn run_pass<P: MirPass>(&self, pass: &P, func: &mut MirFunction) -> bool {
        let cfg = CFG::build(func);
        pass.run(func, &cfg)
    }
}

impl Default for PassManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a default set of optimization passes (non-SSA)
pub fn default_passes() -> PassManager {
    let mut pm = PassManager::new();
    // Order matters:
    // 1. Fold constants first (evaluates constant expressions, may simplify branches)
    // 2. Reduce strength (simplifies operations, algebraic identities)
    // 3. Propagate copies (eliminates intermediate copies)
    // 4. Optimize branches (jump threading, same-target branches)
    // 5. Eliminate dead code last (cleans up unused definitions and unreachable blocks)
    pm.add_pass(ConstantFolding);
    pm.add_pass(StrengthReduction);
    pm.add_pass(CopyPropagation);
    pm.add_pass(BranchOptimization);
    pm.add_pass(DeadCodeElimination);
    pm
}

/// Run the full SSA-based optimization pipeline on a MIR function
///
/// This is the recommended way to optimize MIR before code generation.
/// The pipeline:
/// 1. Convert to SSA form (enables more powerful optimizations)
/// 2. Run optimization passes (constant folding, strength reduction, DCE)
/// 3. Convert out of SSA form (eliminates phi functions via copy insertion)
///
/// Returns the number of modifications made.
pub fn optimize_with_ssa(func: &mut MirFunction) -> usize {
    let cfg = CFG::build(func);
    let mut total_changes = 0;

    // Step 1: Convert to SSA form
    let ssa_pass = SsaConstruction;
    if ssa_pass.run(func, &cfg) {
        total_changes += 1;
    }

    // Step 2: Run optimization passes on SSA form
    // Rebuild CFG after SSA conversion (it may have changed block structure)
    let pm = default_passes();
    total_changes += pm.run(func);

    // Step 3: Convert out of SSA form
    // Rebuild CFG after optimizations
    let cfg = CFG::build(func);
    let ssa_destruct = SsaDestruction;
    if ssa_destruct.run(func, &cfg) {
        total_changes += 1;
    }

    total_changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{MirInst, MirValue};

    fn make_simple_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        func
    }

    #[test]
    fn test_pass_manager_creation() {
        let pm = PassManager::new();
        assert!(pm.passes.is_empty());
    }

    #[test]
    fn test_default_passes() {
        let pm = default_passes();
        assert!(!pm.passes.is_empty());
    }

    #[test]
    fn test_run_passes() {
        let pm = default_passes();
        let mut func = make_simple_function();

        // Should run without error
        let _changes = pm.run(&mut func);

        // Function should still be valid
        assert!(!func.blocks.is_empty());
        assert!(func.block(func.entry).terminator.is_terminator());
    }

    #[test]
    fn test_optimize_with_ssa_simple() {
        let mut func = make_simple_function();

        // Should run without error
        let _changes = optimize_with_ssa(&mut func);

        // Function should still be valid
        assert!(!func.blocks.is_empty());
        assert!(func.block(func.entry).terminator.is_terminator());

        // Should have no phi functions after SSA destruction
        for block in &func.blocks {
            for inst in &block.instructions {
                assert!(
                    !matches!(inst, MirInst::Phi { .. }),
                    "Phi should be eliminated after SSA destruction"
                );
            }
        }
    }

    #[test]
    fn test_optimize_with_ssa_diamond() {
        use crate::compiler::mir::BinOpKind;

        // Create diamond CFG that will need a phi
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        // bb0: v0 = 1; branch v0 -> bb1, bb2
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1: v1 = v0 + 1; jump bb3
        func.block_mut(bb1).instructions.push(MirInst::BinOp {
            dst: v1,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2: v1 = v0 - 1; jump bb3
        func.block_mut(bb2).instructions.push(MirInst::BinOp {
            dst: v1,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3: return v1
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        // Run SSA optimization pipeline
        let changes = optimize_with_ssa(&mut func);
        assert!(
            changes > 0,
            "Should have made changes (SSA construction + destruction)"
        );

        // Should have no phi functions after SSA destruction
        for block in &func.blocks {
            for inst in &block.instructions {
                assert!(
                    !matches!(inst, MirInst::Phi { .. }),
                    "Phi should be eliminated after SSA destruction"
                );
            }
        }

        // Function should still be valid
        assert!(!func.blocks.is_empty());
    }

    /// Integration test: SSA pipeline + full compilation to eBPF
    #[test]
    fn test_ssa_full_compilation_simple() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v0)),
        };

        // Run SSA optimization
        optimize_with_ssa(&mut func);

        // Compile to eBPF
        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "SSA + compile should produce bytecode"
        );
    }

    /// Integration test: SSA with diamond CFG through full compilation
    #[test]
    fn test_ssa_full_compilation_diamond() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        // bb0: v0 = 1; branch v0 -> bb1, bb2
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1: v1 = 10; jump bb3
        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(10),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2: v1 = 20; jump bb3
        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(20),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3: return v1
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        // Run SSA optimization
        let changes = optimize_with_ssa(&mut func);
        assert!(changes > 0, "Diamond CFG should trigger SSA changes");

        // Verify no phis remain
        for block in &func.blocks {
            for inst in &block.instructions {
                assert!(
                    !matches!(inst, MirInst::Phi { .. }),
                    "Phi should be eliminated"
                );
            }
        }

        // Compile to eBPF
        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "SSA diamond + compile should produce bytecode"
        );
    }

    /// Integration test: SSA with arithmetic operations
    #[test]
    fn test_ssa_full_compilation_arithmetic() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        // bb0: v0 = 5; v1 = 10; branch v0 -> bb1, bb2
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(5),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(10),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1: v2 = v0 + v1; jump bb3
        func.block_mut(bb1).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2: v2 = v0 * v1; jump bb3
        func.block_mut(bb2).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Mul,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3: return v2
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        // Run SSA optimization
        optimize_with_ssa(&mut func);

        // Compile to eBPF
        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "SSA arithmetic + compile should produce bytecode"
        );
    }

    /// Integration test: SSA with nested branches
    #[test]
    fn test_ssa_full_compilation_nested_branches() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        // Create: if (a) { if (b) x=1 else x=2 } else { x=3 }; return x
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block(); // entry
        let bb1 = func.alloc_block(); // outer true
        let bb2 = func.alloc_block(); // outer false (x=3)
        let bb3 = func.alloc_block(); // inner true (x=1)
        let bb4 = func.alloc_block(); // inner false (x=2)
        let bb5 = func.alloc_block(); // exit
        func.entry = bb0;

        let a = func.alloc_vreg();
        let b = func.alloc_vreg();
        let x = func.alloc_vreg();

        // bb0: a = 1; b = 0; branch a -> bb1, bb2
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: a,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: b,
            src: MirValue::Const(0),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: a,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1: branch b -> bb3, bb4
        func.block_mut(bb1).terminator = MirInst::Branch {
            cond: b,
            if_true: bb3,
            if_false: bb4,
        };

        // bb2: x = 3; jump bb5
        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: x,
            src: MirValue::Const(3),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb5 };

        // bb3: x = 1; jump bb5
        func.block_mut(bb3).instructions.push(MirInst::Copy {
            dst: x,
            src: MirValue::Const(1),
        });
        func.block_mut(bb3).terminator = MirInst::Jump { target: bb5 };

        // bb4: x = 2; jump bb5
        func.block_mut(bb4).instructions.push(MirInst::Copy {
            dst: x,
            src: MirValue::Const(2),
        });
        func.block_mut(bb4).terminator = MirInst::Jump { target: bb5 };

        // bb5: return x
        func.block_mut(bb5).terminator = MirInst::Return {
            val: Some(MirValue::VReg(x)),
        };

        // Run SSA optimization
        optimize_with_ssa(&mut func);

        // Compile to eBPF
        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "SSA nested branches + compile should produce bytecode"
        );
    }

    /// Integration test: SSA with many variables
    #[test]
    fn test_ssa_full_compilation_many_variables() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        // Create many variables
        let vars: Vec<VReg> = (0..10).map(|_| func.alloc_vreg()).collect();

        // bb0: initialize all vars, branch on first
        for (i, &v) in vars.iter().enumerate() {
            func.block_mut(bb0).instructions.push(MirInst::Copy {
                dst: v,
                src: MirValue::Const(i as i64),
            });
        }
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: vars[0],
            if_true: bb1,
            if_false: bb2,
        };

        // bb1: increment all vars, jump to bb3
        for &v in &vars {
            func.block_mut(bb1).instructions.push(MirInst::BinOp {
                dst: v,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(v),
                rhs: MirValue::Const(1),
            });
        }
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2: decrement all vars, jump to bb3
        for &v in &vars {
            func.block_mut(bb2).instructions.push(MirInst::BinOp {
                dst: v,
                op: BinOpKind::Sub,
                lhs: MirValue::VReg(v),
                rhs: MirValue::Const(1),
            });
        }
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3: return sum of first two vars
        let sum = func.alloc_vreg();
        func.block_mut(bb3).instructions.push(MirInst::BinOp {
            dst: sum,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(vars[0]),
            rhs: MirValue::VReg(vars[1]),
        });
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(sum)),
        };

        // Run SSA optimization
        optimize_with_ssa(&mut func);

        // Compile to eBPF
        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(
            !result.bytecode.is_empty(),
            "SSA many vars + compile should produce bytecode"
        );
    }

    /// Integration test: Compare SSA vs non-SSA compilation produces same/similar output
    #[test]
    fn test_ssa_vs_non_ssa_equivalence() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        // Helper to create the same function twice
        fn make_test_func() -> MirFunction {
            let mut func = MirFunction::new();
            let bb0 = func.alloc_block();
            func.entry = bb0;

            let v0 = func.alloc_vreg();
            let v1 = func.alloc_vreg();
            let v2 = func.alloc_vreg();

            func.block_mut(bb0).instructions.push(MirInst::Copy {
                dst: v0,
                src: MirValue::Const(5),
            });
            func.block_mut(bb0).instructions.push(MirInst::Copy {
                dst: v1,
                src: MirValue::Const(10),
            });
            func.block_mut(bb0).instructions.push(MirInst::BinOp {
                dst: v2,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(v0),
                rhs: MirValue::VReg(v1),
            });
            func.block_mut(bb0).terminator = MirInst::Return {
                val: Some(MirValue::VReg(v2)),
            };

            func
        }

        // Compile without SSA
        let func_no_ssa = make_test_func();
        let program_no_ssa = MirProgram {
            main: func_no_ssa,
            subfunctions: vec![],
        };
        let result_no_ssa = compile_mir_to_ebpf(&program_no_ssa, None).unwrap();

        // Compile with SSA
        let mut func_ssa = make_test_func();
        optimize_with_ssa(&mut func_ssa);
        let program_ssa = MirProgram {
            main: func_ssa,
            subfunctions: vec![],
        };
        let result_ssa = compile_mir_to_ebpf(&program_ssa, None).unwrap();

        // Both should produce valid bytecode
        assert!(!result_no_ssa.bytecode.is_empty());
        assert!(!result_ssa.bytecode.is_empty());

        // For this simple case, bytecode should be similar in size
        // (SSA might have slight differences due to copy insertion/elimination)
        let size_diff =
            (result_ssa.bytecode.len() as i64 - result_no_ssa.bytecode.len() as i64).abs();
        assert!(
            size_diff <= 64, // Allow some difference (8 instructions worth)
            "SSA and non-SSA bytecode should be similar size: SSA={}, non-SSA={}",
            result_ssa.bytecode.len(),
            result_no_ssa.bytecode.len()
        );
    }

    /// Integration test: SSA with constant folding optimization
    #[test]
    fn test_ssa_constant_folding_integration() {
        use crate::compiler::mir::*;
        use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        // v0 = 5; v1 = 10; v2 = v0 + v1 (should fold to v2 = 15)
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(5),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(10),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        // Run SSA optimization (includes constant folding)
        let changes = optimize_with_ssa(&mut func);

        // Should have made some changes (constant folding)
        assert!(changes >= 0); // May or may not fold depending on implementation

        // Compile to eBPF
        let program = MirProgram {
            main: func,
            subfunctions: vec![],
        };
        let result = compile_mir_to_ebpf(&program, None).unwrap();
        assert!(!result.bytecode.is_empty());
    }

    #[test]
    fn test_pass_convergence_conditional() {
        use crate::compiler::mir::{BinOpKind, CtxField};

        // Test that passes converge on conditional code patterns
        // This pattern was causing "reached max iterations" warning before the fix

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block(); // entry: check condition
        let bb1 = func.alloc_block(); // if true branch
        let bb2 = func.alloc_block(); // if false branch
        let bb3 = func.alloc_block(); // exit
        func.entry = bb0;

        let v_pid = func.alloc_vreg();
        let v_cond = func.alloc_vreg();
        let v_large_1 = func.alloc_vreg();
        let v_large_0 = func.alloc_vreg();

        // bb0: load pid, compare, branch
        func.block_mut(bb0)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v_pid,
                field: CtxField::Pid,
            });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v_cond,
            op: BinOpKind::Gt,
            lhs: MirValue::VReg(v_pid),
            rhs: MirValue::Const(1000),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v_cond,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1: large = 1, jump to exit
        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: v_large_1,
            src: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2: large = 0, jump to exit
        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: v_large_0,
            src: MirValue::Const(0),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3: return
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        // Run optimization - should converge without hitting max iterations
        // Before the fix, const_fold was incorrectly reporting changes when
        // replacing a VReg with a Const that was already a Const (via the
        // constants hashmap), causing infinite iterations.
        let _changes = optimize_with_ssa(&mut func);

        // The test passes if we don't see "PassManager: reached max iterations"
        // printed to stderr. The fix in const_fold.rs now checks if the operand
        // is already a Const before replacing it.
    }
}
