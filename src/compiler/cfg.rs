//! Control Flow Graph construction and analysis
//!
//! This module builds a CFG from MIR and provides analysis capabilities:
//! - Predecessor/successor relationships
//! - Dominator tree
//! - Liveness analysis for register allocation
//! - Loop detection

use std::collections::{HashMap, HashSet, VecDeque};

use super::mir::{BasicBlock, BlockId, MirFunction, MirInst, VReg};
mod analysis;
mod mir_analysis;
pub use mir_analysis::compute_live_intervals;

/// Instruction adapter for generic CFG/liveness analysis.
pub trait CfgInst {
    fn defs(&self) -> Vec<VReg>;
    fn uses(&self) -> Vec<VReg>;
}

/// Basic block adapter for generic CFG/liveness analysis.
pub trait CfgBlock {
    type Inst: CfgInst;
    fn id(&self) -> BlockId;
    fn instructions(&self) -> &[Self::Inst];
    fn terminator(&self) -> &Self::Inst;
    fn successors(&self) -> Vec<BlockId>;
}

/// Function adapter for generic CFG/liveness analysis.
pub trait CfgFunction {
    type Inst: CfgInst;
    type Block: CfgBlock<Inst = Self::Inst>;
    fn entry(&self) -> BlockId;
    fn blocks(&self) -> &[Self::Block];
    fn block(&self, id: BlockId) -> &Self::Block;
    fn has_block(&self, id: BlockId) -> bool;
}

impl CfgInst for MirInst {
    fn defs(&self) -> Vec<VReg> {
        self.def().into_iter().collect()
    }

    fn uses(&self) -> Vec<VReg> {
        self.uses()
    }
}

impl CfgBlock for BasicBlock {
    type Inst = MirInst;

    fn id(&self) -> BlockId {
        self.id
    }

    fn instructions(&self) -> &[Self::Inst] {
        &self.instructions
    }

    fn terminator(&self) -> &Self::Inst {
        &self.terminator
    }

    fn successors(&self) -> Vec<BlockId> {
        self.successors()
    }
}

impl CfgFunction for MirFunction {
    type Inst = MirInst;
    type Block = BasicBlock;

    fn entry(&self) -> BlockId {
        self.entry
    }

    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }

    fn block(&self, id: BlockId) -> &Self::Block {
        MirFunction::block(self, id)
    }

    fn has_block(&self, id: BlockId) -> bool {
        MirFunction::has_block(self, id)
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisCfg {
    pub entry: BlockId,
    pub predecessors: HashMap<BlockId, Vec<BlockId>>,
    pub successors: HashMap<BlockId, Vec<BlockId>>,
    pub idom: HashMap<BlockId, BlockId>,
    pub rpo: Vec<BlockId>,
    pub post_order: Vec<BlockId>,
}

#[derive(Debug, Clone)]
pub struct BlockLiveness {
    pub live_in: HashMap<BlockId, HashSet<VReg>>,
    pub live_out: HashMap<BlockId, HashSet<VReg>>,
}

#[derive(Debug, Clone)]
pub struct GenericLoopInfo {
    pub loops: HashMap<BlockId, HashSet<BlockId>>,
    pub loop_depth: HashMap<BlockId, usize>,
}

/// Control Flow Graph built from MIR
#[derive(Debug)]
pub struct CFG {
    /// Entry block
    pub entry: BlockId,
    /// Predecessors for each block
    pub predecessors: HashMap<BlockId, Vec<BlockId>>,
    /// Successors for each block (computed from terminators)
    pub successors: HashMap<BlockId, Vec<BlockId>>,
    /// Immediate dominator for each block
    pub idom: HashMap<BlockId, BlockId>,
    /// Reverse post-order traversal (for dataflow analysis)
    pub rpo: Vec<BlockId>,
    /// Post-order traversal
    pub post_order: Vec<BlockId>,
    /// Dominance frontiers for each block (used in SSA construction)
    pub dominance_frontiers: HashMap<BlockId, HashSet<BlockId>>,
}

/// Liveness analysis results
#[derive(Debug)]
pub struct LivenessInfo {
    /// Virtual registers live at the start of each block
    pub live_in: HashMap<BlockId, HashSet<VReg>>,
    /// Virtual registers live at the end of each block
    pub live_out: HashMap<BlockId, HashSet<VReg>>,
    /// Def-use chains: for each vreg, list of (block, instruction index) where it's defined/used
    pub defs: HashMap<VReg, Vec<(BlockId, usize)>>,
    pub uses: HashMap<VReg, Vec<(BlockId, usize)>>,
}

/// Live interval for a virtual register (used in register allocation)
#[derive(Debug, Clone)]
pub struct LiveInterval {
    pub vreg: VReg,
    /// Start point (instruction index in linearized program)
    pub start: usize,
    /// End point (instruction index in linearized program)
    pub end: usize,
    /// All use points
    pub use_points: Vec<usize>,
}

/// Loop information
#[derive(Debug)]
pub struct LoopInfo {
    /// Natural loops: header -> set of blocks in loop
    pub loops: HashMap<BlockId, HashSet<BlockId>>,
    /// Loop depth for each block (0 = not in a loop)
    pub loop_depth: HashMap<BlockId, usize>,
}

#[cfg(test)]
mod tests;
