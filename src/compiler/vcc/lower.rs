struct VccLowerer<'a> {
    func: &'a MirFunction,
    types: &'a HashMap<VReg, MirType>,
    subfn_summaries:
        &'a HashMap<SubfunctionId, crate::compiler::subfn_summaries::SubfunctionReturnSummary>,
    program: Option<&'a ProgramTypeInfo>,
    probe_ctx: Option<&'a ProbeContext>,
    slot_sizes: HashMap<StackSlotId, usize>,
    slot_kinds: HashMap<StackSlotId, StackSlotKind>,
    list_max: HashMap<StackSlotId, usize>,
    ptr_regs: HashMap<VccReg, VccPointerInfo>,
    entry_ctx_field_regs: HashMap<String, VccReg>,
    direct_ctx_field_regs: HashMap<VccReg, CtxField>,
    next_temp: u32,
}

const STRING_APPEND_COPY_CAP: usize = 64;
const MAX_INT_STRING_LEN: usize = 20;

#[path = "lower/value_utils.rs"]
mod value_utils;
#[path = "lower/helper_checks.rs"]
mod helper_checks;
#[path = "lower/context_checks.rs"]
mod context_checks;
#[path = "lower/instruction_lowering.rs"]
mod instruction_lowering;

impl<'a> VccLowerer<'a> {
    fn seed_vcc_type_for(
        func: &MirFunction,
        slot_sizes: &HashMap<StackSlotId, usize>,
        vreg: VReg,
        ty: &MirType,
    ) -> VccValueType {
        let Some(slot) = func.param_stack_slots.get(&(vreg.0 as usize)).copied() else {
            let mut seeded = vcc_type_from_mir(ty);
            if func.param_trusted_btf.contains(&(vreg.0 as usize))
                && let VccValueType::Ptr(info) = &mut seeded
                && info.space == VccAddrSpace::Kernel
            {
                info.space = VccAddrSpace::KernelBtf;
            }
            if func.param_non_null.contains(&(vreg.0 as usize))
                && let VccValueType::Ptr(info) = &mut seeded
            {
                info.nullability = VccNullability::NonNull;
            }
            return seeded;
        };
        let VccValueType::Ptr(mut info) = vcc_type_from_mir(ty) else {
            return vcc_type_from_mir(ty);
        };
        if !matches!(info.space, VccAddrSpace::Stack(_)) {
            return VccValueType::Ptr(info);
        }
        info.space = VccAddrSpace::Stack(slot);
        info.bounds = slot_sizes
            .get(&slot)
            .copied()
            .and_then(|size| stack_bounds(size as i64));
        VccValueType::Ptr(info)
    }

    fn seed_vcc_type(&self, vreg: VReg, ty: &MirType) -> VccValueType {
        Self::seed_vcc_type_for(self.func, &self.slot_sizes, vreg, ty)
    }

    fn new(
        func: &'a MirFunction,
        types: &'a HashMap<VReg, MirType>,
        list_max: HashMap<StackSlotId, usize>,
        subfn_summaries: &'a HashMap<
            SubfunctionId,
            crate::compiler::subfn_summaries::SubfunctionReturnSummary,
        >,
        program: Option<&'a ProgramTypeInfo>,
        probe_ctx: Option<&'a ProbeContext>,
    ) -> Self {
        let mut slot_sizes = HashMap::new();
        let mut slot_kinds = HashMap::new();
        for slot in &func.stack_slots {
            slot_sizes.insert(slot.id, slot.size);
            slot_kinds.insert(slot.id, slot.kind);
        }
        let mut ptr_regs = HashMap::new();
        for (vreg, ty) in types {
            if let VccValueType::Ptr(info) = Self::seed_vcc_type_for(func, &slot_sizes, *vreg, ty)
            {
                ptr_regs.insert(VccReg(vreg.0), info);
            }
        }
        Self {
            func,
            types,
            subfn_summaries,
            program,
            probe_ctx,
            slot_sizes,
            slot_kinds,
            list_max,
            ptr_regs,
            entry_ctx_field_regs: HashMap::new(),
            direct_ctx_field_regs: HashMap::new(),
            next_temp: func.vreg_count.max(func.param_count as u32),
        }
    }

    fn seed_types(&self) -> HashMap<VccReg, VccValueType> {
        let mut seed = HashMap::new();
        for (vreg, ty) in self.types {
            seed.insert(VccReg(vreg.0), self.seed_vcc_type(*vreg, ty));
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
            entry_initialized_dynptr_slots: self.func.entry_initialized_dynptr_slots.clone(),
            reg_count: self.next_temp,
        })
    }

}
