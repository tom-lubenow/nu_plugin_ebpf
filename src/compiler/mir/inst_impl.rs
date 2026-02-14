use super::*;

impl MirInst {
    /// Returns true if this instruction is a terminator
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            MirInst::Jump { .. }
                | MirInst::Branch { .. }
                | MirInst::Return { .. }
                | MirInst::TailCall { .. }
        )
    }

    /// Visit all virtual registers used as operands by this instruction.
    ///
    /// This walks use sites only (not destination definitions) so passes can
    /// safely rewrite operands in-place.
    pub fn visit_uses_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut VReg),
    {
        macro_rules! visit_value {
            ($value:expr) => {
                if let MirValue::VReg(vreg) = $value {
                    f(vreg);
                }
            };
        }

        match self {
            MirInst::Copy { src, .. } => visit_value!(src),
            MirInst::Load { ptr, .. } => f(ptr),
            MirInst::Store { ptr, val, .. } => {
                f(ptr);
                visit_value!(val);
            }
            MirInst::LoadSlot { .. } => {}
            MirInst::StoreSlot { val, .. } => visit_value!(val),
            MirInst::BinOp { lhs, rhs, .. } => {
                visit_value!(lhs);
                visit_value!(rhs);
            }
            MirInst::UnaryOp { src, .. } => visit_value!(src),
            MirInst::CallHelper { args, .. } => {
                for arg in args {
                    visit_value!(arg);
                }
            }
            MirInst::CallKfunc { args, .. } | MirInst::CallSubfn { args, .. } => {
                for arg in args {
                    f(arg);
                }
            }
            MirInst::MapLookup { key, .. } => f(key),
            MirInst::MapUpdate { key, val, .. } => {
                f(key);
                f(val);
            }
            MirInst::MapDelete { key, .. } => f(key),
            MirInst::Histogram { value, .. } => f(value),
            MirInst::StartTimer => {}
            MirInst::StopTimer { .. } => {}
            MirInst::EmitEvent { data, .. } => f(data),
            MirInst::EmitRecord { fields } => {
                for field in fields {
                    f(&mut field.value);
                }
            }
            MirInst::LoadCtxField { .. } => {}
            MirInst::ReadStr { ptr, .. } => f(ptr),
            MirInst::StrCmp { .. } => {}
            MirInst::RecordStore { val, .. } => visit_value!(val),
            MirInst::ListNew { .. } => {}
            MirInst::ListPush { list, item } => {
                f(list);
                f(item);
            }
            MirInst::ListLen { list, .. } => f(list),
            MirInst::ListGet { list, idx, .. } => {
                f(list);
                visit_value!(idx);
            }
            MirInst::Jump { .. } => {}
            MirInst::Branch { cond, .. } => f(cond),
            MirInst::Return { val } => {
                if let Some(value) = val {
                    visit_value!(value);
                }
            }
            MirInst::TailCall { index, .. } => visit_value!(index),
            MirInst::LoopHeader { .. } => {}
            MirInst::LoopBack { counter, .. } => f(counter),
            MirInst::Placeholder => {}
            MirInst::Phi { args, .. } => {
                for (_, vreg) in args {
                    f(vreg);
                }
            }
            MirInst::StringAppend { dst_len, val, .. } => {
                f(dst_len);
                visit_value!(val);
            }
            MirInst::IntToString { dst_len, val, .. } => {
                f(dst_len);
                f(val);
            }
        }
    }

    /// Return a copy of this instruction with all operand vregs rewritten.
    pub fn map_uses<F>(&self, mut map: F) -> MirInst
    where
        F: FnMut(VReg) -> VReg,
    {
        let mut cloned = self.clone();
        cloned.visit_uses_mut(|vreg| *vreg = map(*vreg));
        cloned
    }

    /// Returns the destination register if this instruction writes to one
    pub fn def(&self) -> Option<VReg> {
        match self {
            MirInst::Copy { dst, .. }
            | MirInst::Load { dst, .. }
            | MirInst::LoadSlot { dst, .. }
            | MirInst::BinOp { dst, .. }
            | MirInst::UnaryOp { dst, .. }
            | MirInst::CallHelper { dst, .. }
            | MirInst::CallKfunc { dst, .. }
            | MirInst::CallSubfn { dst, .. }
            | MirInst::MapLookup { dst, .. }
            | MirInst::LoadCtxField { dst, .. }
            | MirInst::StrCmp { dst, .. }
            | MirInst::StopTimer { dst, .. }
            | MirInst::LoopHeader { counter: dst, .. }
            | MirInst::ListNew { dst, .. }
            | MirInst::ListLen { dst, .. }
            | MirInst::ListGet { dst, .. }
            | MirInst::Phi { dst, .. } => Some(*dst),
            _ => None,
        }
    }

    /// Returns virtual registers used by this instruction
    pub fn uses(&self) -> Vec<VReg> {
        let mut uses = Vec::new();
        let add_value = |uses: &mut Vec<VReg>, v: &MirValue| {
            if let MirValue::VReg(r) = v {
                uses.push(*r);
            }
        };

        match self {
            MirInst::Copy { src, .. } => add_value(&mut uses, src),
            MirInst::Load { ptr, .. } => uses.push(*ptr),
            MirInst::Store { ptr, val, .. } => {
                uses.push(*ptr);
                add_value(&mut uses, val);
            }
            MirInst::LoadSlot { .. } => {}
            MirInst::StoreSlot { val, .. } => add_value(&mut uses, val),
            MirInst::BinOp { lhs, rhs, .. } => {
                add_value(&mut uses, lhs);
                add_value(&mut uses, rhs);
            }
            MirInst::UnaryOp { src, .. } => add_value(&mut uses, src),
            MirInst::CallHelper { args, .. } => {
                for arg in args {
                    add_value(&mut uses, arg);
                }
            }
            MirInst::CallKfunc { args, .. } => {
                for arg in args {
                    uses.push(*arg);
                }
            }
            MirInst::CallSubfn { args, .. } => {
                for arg in args {
                    uses.push(*arg);
                }
            }
            MirInst::MapLookup { key, .. } => uses.push(*key),
            MirInst::MapUpdate { key, val, .. } => {
                uses.push(*key);
                uses.push(*val);
            }
            MirInst::MapDelete { key, .. } => uses.push(*key),
            MirInst::Histogram { value, .. } => uses.push(*value),
            MirInst::StartTimer => {}
            MirInst::StopTimer { .. } => {}
            MirInst::EmitEvent { data, .. } => uses.push(*data),
            MirInst::EmitRecord { fields } => {
                for field in fields {
                    uses.push(field.value);
                }
            }
            MirInst::LoadCtxField { .. } => {}
            MirInst::ReadStr { ptr, .. } => uses.push(*ptr),
            MirInst::StrCmp { .. } => {}
            MirInst::RecordStore { val, .. } => add_value(&mut uses, val),
            MirInst::ListNew { .. } => {}
            MirInst::ListPush { list, item } => {
                uses.push(*list);
                uses.push(*item);
            }
            MirInst::ListLen { list, .. } => uses.push(*list),
            MirInst::ListGet { list, idx, .. } => {
                uses.push(*list);
                add_value(&mut uses, idx);
            }
            MirInst::Jump { .. } => {}
            MirInst::Branch { cond, .. } => uses.push(*cond),
            MirInst::Return { val } => {
                if let Some(v) = val {
                    add_value(&mut uses, v);
                }
            }
            MirInst::TailCall { index, .. } => add_value(&mut uses, index),
            MirInst::LoopHeader { counter, .. } => uses.push(*counter),
            MirInst::LoopBack { counter, .. } => uses.push(*counter),
            MirInst::Placeholder => {}
            MirInst::Phi { args, .. } => {
                for (_, vreg) in args {
                    uses.push(*vreg);
                }
            }
            MirInst::StringAppend { dst_len, val, .. } => {
                uses.push(*dst_len);
                add_value(&mut uses, val);
            }
            MirInst::IntToString { dst_len, val, .. } => {
                uses.push(*dst_len);
                uses.push(*val);
            }
        }
        uses
    }
}
