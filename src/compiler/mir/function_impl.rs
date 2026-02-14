use super::*;

impl BasicBlock {
    /// Create a new basic block
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            terminator: MirInst::Placeholder, // Must be replaced with a real terminator
        }
    }

    /// Get successor block IDs
    pub fn successors(&self) -> Vec<BlockId> {
        match &self.terminator {
            MirInst::Jump { target } => vec![*target],
            MirInst::Branch {
                if_true, if_false, ..
            } => vec![*if_true, *if_false],
            MirInst::LoopHeader { body, exit, .. } => vec![*body, *exit],
            MirInst::LoopBack { header, .. } => vec![*header],
            MirInst::Return { .. } | MirInst::TailCall { .. } => vec![],
            MirInst::Placeholder => vec![],
            _ => panic!("Invalid terminator: {:?}", self.terminator),
        }
    }
}

impl MirFunction {
    /// Create a new empty MIR function
    pub fn new() -> Self {
        Self {
            name: None,
            blocks: Vec::new(),
            entry: BlockId(0),
            vreg_count: 0,
            stack_slots: Vec::new(),
            maps_used: Vec::new(),
            param_count: 0,
        }
    }

    /// Create a new named MIR function (for subfunctions)
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new()
        }
    }

    /// Allocate a new virtual register
    pub fn alloc_vreg(&mut self) -> VReg {
        let vreg = VReg(self.vreg_count);
        self.vreg_count += 1;
        vreg
    }

    /// Allocate a new stack slot
    pub fn alloc_stack_slot(
        &mut self,
        size: usize,
        align: usize,
        kind: StackSlotKind,
    ) -> StackSlotId {
        let id = StackSlotId(self.stack_slots.len() as u32);
        self.stack_slots.push(StackSlot {
            id,
            size,
            align,
            kind,
            offset: None,
        });
        id
    }

    /// Allocate a new basic block
    pub fn alloc_block(&mut self) -> BlockId {
        let id = BlockId(self.blocks.len() as u32);
        self.blocks.push(BasicBlock::new(id));
        id
    }

    /// Get a mutable reference to a block
    pub fn block_mut(&mut self, id: BlockId) -> &mut BasicBlock {
        let idx = id.0 as usize;
        let fast_path = self.blocks.get(idx).is_some_and(|b| b.id == id);
        if fast_path {
            return &mut self.blocks[idx];
        }
        self.blocks
            .iter_mut()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("Block {:?} not found", id))
    }

    /// Get a reference to a block
    pub fn block(&self, id: BlockId) -> &BasicBlock {
        let idx = id.0 as usize;
        if let Some(block) = self.blocks.get(idx)
            && block.id == id
        {
            return block;
        }
        self.blocks
            .iter()
            .find(|b| b.id == id)
            .unwrap_or_else(|| panic!("Block {:?} not found", id))
    }

    /// Check if a block exists
    pub fn has_block(&self, id: BlockId) -> bool {
        let idx = id.0 as usize;
        if self.blocks.get(idx).is_some_and(|b| b.id == id) {
            return true;
        }
        self.blocks.iter().any(|b| b.id == id)
    }
}

impl Default for MirFunction {
    fn default() -> Self {
        Self::new()
    }
}

impl MirProgram {
    pub fn new(main: MirFunction) -> Self {
        Self {
            main,
            subfunctions: Vec::new(),
        }
    }

    /// Add a subfunction and return its ID
    pub fn add_subfunction(&mut self, func: MirFunction) -> SubfunctionId {
        let id = SubfunctionId(self.subfunctions.len() as u32);
        self.subfunctions.push(func);
        id
    }

    /// Get a subfunction by ID
    pub fn get_subfunction(&self, id: SubfunctionId) -> Option<&MirFunction> {
        self.subfunctions.get(id.0 as usize)
    }

    /// Get a mutable reference to a subfunction by ID
    pub fn get_subfunction_mut(&mut self, id: SubfunctionId) -> Option<&mut MirFunction> {
        self.subfunctions.get_mut(id.0 as usize)
    }
}
