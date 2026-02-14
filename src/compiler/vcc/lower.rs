struct VccLowerer<'a> {
    func: &'a MirFunction,
    types: &'a HashMap<VReg, MirType>,
    slot_sizes: HashMap<StackSlotId, usize>,
    slot_kinds: HashMap<StackSlotId, StackSlotKind>,
    list_max: HashMap<StackSlotId, usize>,
    ptr_regs: HashMap<VccReg, VccPointerInfo>,
    entry_ctx_field_regs: HashMap<String, VccReg>,
    next_temp: u32,
}

const STRING_APPEND_COPY_CAP: usize = 64;
const MAX_INT_STRING_LEN: usize = 20;

#[path = "lower/value_utils.rs"]
mod value_utils;
#[path = "lower/helper_checks.rs"]
mod helper_checks;
#[path = "lower/instruction_lowering.rs"]
mod instruction_lowering;

impl<'a> VccLowerer<'a> {
    fn new(
        func: &'a MirFunction,
        types: &'a HashMap<VReg, MirType>,
        list_max: HashMap<StackSlotId, usize>,
    ) -> Self {
        let mut slot_sizes = HashMap::new();
        let mut slot_kinds = HashMap::new();
        for slot in &func.stack_slots {
            slot_sizes.insert(slot.id, slot.size);
            slot_kinds.insert(slot.id, slot.kind);
        }
        let mut ptr_regs = HashMap::new();
        for (vreg, ty) in types {
            if let VccValueType::Ptr(info) = vcc_type_from_mir(ty) {
                ptr_regs.insert(VccReg(vreg.0), info);
            }
        }
        Self {
            func,
            types,
            slot_sizes,
            slot_kinds,
            list_max,
            ptr_regs,
            entry_ctx_field_regs: HashMap::new(),
            next_temp: func.vreg_count.max(func.param_count as u32),
        }
    }

    fn seed_types(&self) -> HashMap<VccReg, VccValueType> {
        let mut seed = HashMap::new();
        for (vreg, ty) in self.types {
            seed.insert(VccReg(vreg.0), vcc_type_from_mir(ty));
        }
        seed
    }

    fn lower(&mut self) -> Result<VccFunction, VccError> {
        let max_block = self.func.blocks.iter().map(|b| b.id.0).max().unwrap_or(0) as usize;
        let mut blocks = Vec::with_capacity(max_block + 1);
        for i in 0..=max_block {
            blocks.push(VccBlock {
                id: VccBlockId(i as u32),
                instructions: Vec::new(),
                terminator: VccTerminator::Return { value: None },
            });
        }

        for block in &self.func.blocks {
            let mut insts = Vec::new();
            let in_entry = block.id == self.func.entry;
            for inst in &block.instructions {
                self.lower_inst(inst, &mut insts, in_entry)?;
            }
            let term = self.lower_terminator(&block.terminator, &mut insts)?;
            let idx = block.id.0 as usize;
            blocks[idx] = VccBlock {
                id: VccBlockId(block.id.0),
                instructions: insts,
                terminator: term,
            };
        }

        Ok(VccFunction {
            entry: VccBlockId(self.func.entry.0),
            blocks,
            reg_count: self.next_temp,
        })
    }

}
