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
mod list_lowering;
mod ssa;
mod ssa_destruct;
mod strength;

pub use branch_opt::BranchOptimization;
pub use const_fold::ConstantFolding;
pub use copy_prop::CopyPropagation;
pub use dce::DeadCodeElimination;
pub use list_lowering::ListLowering;
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

            // Rebuild CFG before each pass so no pass observes stale graph
            // analyses after an earlier pass mutates control flow.
            for pass in &self.passes {
                let cfg = CFG::build(func);
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

    // Step 4: Lower list operations into explicit loads/stores with bounds checks
    let cfg = CFG::build(func);
    let list_lowering = ListLowering;
    if list_lowering.run(func, &cfg) {
        total_changes += 1;
    }

    total_changes
}

#[cfg(test)]
mod tests;
