//! Copy Propagation pass
//!
//! This pass replaces uses of copy destinations with their sources:
//! ```text
//! v1 = v0
//! v2 = v1 + 3   =>   v2 = v0 + 3
//! ```
//!
//! After propagation, the original copy may become dead and can be removed by DCE.
//!
//! This pass is particularly useful after SSA destruction, which inserts copies
//! to eliminate phi functions. Copy propagation cleans up those copies.

use std::collections::HashMap;

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{MirFunction, MirInst, MirValue, VReg};

/// Copy Propagation pass
pub struct CopyPropagation;

impl MirPass for CopyPropagation {
    fn name(&self) -> &str {
        "copy_prop"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let mut changed = false;

        // Build copy map: dst -> src (transitively resolved)
        let copy_map = self.build_copy_map(func);

        if copy_map.is_empty() {
            return false;
        }

        // Replace uses of copy destinations with sources
        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if self.propagate_copies(inst, &copy_map) {
                    changed = true;
                }
            }
            if self.propagate_copies_in_terminator(&mut block.terminator, &copy_map) {
                changed = true;
            }
        }

        changed
    }
}

impl CopyPropagation {
    /// Build a map from copy destinations to their (transitively resolved) sources
    fn build_copy_map(&self, func: &MirFunction) -> HashMap<VReg, VReg> {
        let mut copy_map: HashMap<VReg, VReg> = HashMap::new();

        // First pass: collect direct copies (vreg to vreg only)
        for block in &func.blocks {
            for inst in &block.instructions {
                if let MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src),
                } = inst
                {
                    // Don't propagate self-copies
                    if dst != src {
                        copy_map.insert(*dst, *src);
                    }
                }
            }
        }

        // Resolve transitive copies: if v2 = v1 and v1 = v0, then v2 -> v0
        // We need to be careful about cycles (shouldn't happen in well-formed SSA)
        let mut resolved: HashMap<VReg, VReg> = HashMap::new();

        for &dst in copy_map.keys() {
            let src = self.resolve_copy_chain(dst, &copy_map);
            if src != dst {
                resolved.insert(dst, src);
            }
        }

        resolved
    }

    /// Follow the copy chain to find the ultimate source
    fn resolve_copy_chain(&self, start: VReg, copy_map: &HashMap<VReg, VReg>) -> VReg {
        let mut current = start;
        let mut visited = std::collections::HashSet::new();

        while let Some(&src) = copy_map.get(&current) {
            // Detect cycles (shouldn't happen, but be safe)
            if !visited.insert(current) {
                break;
            }
            current = src;
        }

        current
    }

    /// Propagate copies in an instruction's operands
    fn propagate_copies(&self, inst: &mut MirInst, copy_map: &HashMap<VReg, VReg>) -> bool {
        let mut changed = false;

        match inst {
            // Don't modify the copy instruction itself - just its uses elsewhere
            MirInst::Copy { src, .. } => {
                if self.replace_value(src, copy_map) {
                    changed = true;
                }
            }

            MirInst::BinOp { lhs, rhs, .. } => {
                if self.replace_value(lhs, copy_map) {
                    changed = true;
                }
                if self.replace_value(rhs, copy_map) {
                    changed = true;
                }
            }

            MirInst::UnaryOp { src, .. } => {
                if self.replace_value(src, copy_map) {
                    changed = true;
                }
            }

            MirInst::Load { ptr, .. } => {
                if let Some(&new_ptr) = copy_map.get(ptr) {
                    *ptr = new_ptr;
                    changed = true;
                }
            }

            MirInst::Store { ptr, val, .. } => {
                if let Some(&new_ptr) = copy_map.get(ptr) {
                    *ptr = new_ptr;
                    changed = true;
                }
                if self.replace_value(val, copy_map) {
                    changed = true;
                }
            }

            MirInst::StoreSlot { val, .. } => {
                if self.replace_value(val, copy_map) {
                    changed = true;
                }
            }

            MirInst::RecordStore { val, .. } => {
                if self.replace_value(val, copy_map) {
                    changed = true;
                }
            }

            MirInst::CallHelper { args, .. } => {
                for arg in args {
                    if self.replace_value(arg, copy_map) {
                        changed = true;
                    }
                }
            }

            MirInst::CallSubfn { args, .. } => {
                for arg in args {
                    if let Some(&new_arg) = copy_map.get(arg) {
                        *arg = new_arg;
                        changed = true;
                    }
                }
            }

            MirInst::MapLookup { key, .. } => {
                if let Some(&new_key) = copy_map.get(key) {
                    *key = new_key;
                    changed = true;
                }
            }

            MirInst::MapUpdate { key, val, .. } => {
                if let Some(&new_key) = copy_map.get(key) {
                    *key = new_key;
                    changed = true;
                }
                if let Some(&new_val) = copy_map.get(val) {
                    *val = new_val;
                    changed = true;
                }
            }

            MirInst::MapDelete { key, .. } => {
                if let Some(&new_key) = copy_map.get(key) {
                    *key = new_key;
                    changed = true;
                }
            }

            MirInst::EmitEvent { data, .. } => {
                if let Some(&new_data) = copy_map.get(data) {
                    *data = new_data;
                    changed = true;
                }
            }

            MirInst::EmitRecord { fields, .. } => {
                // RecordFieldDef contains VReg that may be propagated
                for field in fields {
                    if let Some(&new_val) = copy_map.get(&field.value) {
                        field.value = new_val;
                        changed = true;
                    }
                }
            }

            MirInst::ReadStr { ptr, .. } => {
                if let Some(&new_ptr) = copy_map.get(ptr) {
                    *ptr = new_ptr;
                    changed = true;
                }
            }

            // StrCmp uses StackSlotIds, not VRegs - nothing to propagate
            MirInst::StrCmp { .. } => {}

            MirInst::Histogram { value, .. } => {
                if let Some(&new_val) = copy_map.get(value) {
                    *value = new_val;
                    changed = true;
                }
            }

            // StopTimer only has dst (output), no vreg inputs to propagate
            MirInst::StopTimer { .. } => {}

            MirInst::Phi { args, .. } => {
                for (_, vreg) in args {
                    if let Some(&new_vreg) = copy_map.get(vreg) {
                        *vreg = new_vreg;
                        changed = true;
                    }
                }
            }

            // List operations
            MirInst::ListNew { .. } => {}

            MirInst::ListPush { list, item } => {
                if let Some(&new_list) = copy_map.get(list) {
                    *list = new_list;
                    changed = true;
                }
                if let Some(&new_item) = copy_map.get(item) {
                    *item = new_item;
                    changed = true;
                }
            }

            MirInst::ListLen { list, .. } => {
                if let Some(&new_list) = copy_map.get(list) {
                    *list = new_list;
                    changed = true;
                }
            }

            MirInst::ListGet { list, idx, .. } => {
                if let Some(&new_list) = copy_map.get(list) {
                    *list = new_list;
                    changed = true;
                }
                if self.replace_value(idx, copy_map) {
                    changed = true;
                }
            }

            // No operands to propagate
            MirInst::LoadSlot { .. }
            | MirInst::LoadCtxField { .. }
            | MirInst::StartTimer
            | MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::Return { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopHeader { .. }
            | MirInst::LoopBack { .. } => {}

            MirInst::StringAppend { dst_len, val, .. } => {
                if let Some(&copy_src) = copy_map.get(dst_len) {
                    *dst_len = copy_src;
                    changed = true;
                }
                if let MirValue::VReg(vreg) = val {
                    if let Some(&copy_src) = copy_map.get(vreg) {
                        *val = MirValue::VReg(copy_src);
                        changed = true;
                    }
                }
            }
            MirInst::IntToString { dst_len, val, .. } => {
                if let Some(&copy_src) = copy_map.get(dst_len) {
                    *dst_len = copy_src;
                    changed = true;
                }
                if let Some(&copy_src) = copy_map.get(val) {
                    *val = copy_src;
                    changed = true;
                }
            }
        }

        changed
    }

    /// Propagate copies in terminator instructions
    fn propagate_copies_in_terminator(
        &self,
        term: &mut MirInst,
        copy_map: &HashMap<VReg, VReg>,
    ) -> bool {
        let mut changed = false;

        match term {
            MirInst::Branch { cond, .. } => {
                if let Some(&new_cond) = copy_map.get(cond) {
                    *cond = new_cond;
                    changed = true;
                }
            }

            MirInst::Return { val } => {
                if let Some(v) = val {
                    if self.replace_value(v, copy_map) {
                        changed = true;
                    }
                }
            }

            MirInst::TailCall { index, .. } => {
                if self.replace_value(index, copy_map) {
                    changed = true;
                }
            }

            MirInst::LoopBack { counter, .. } => {
                if let Some(&new_counter) = copy_map.get(counter) {
                    *counter = new_counter;
                    changed = true;
                }
            }

            // No vregs to propagate
            MirInst::Jump { .. } | MirInst::LoopHeader { .. } => {}

            // Non-terminators shouldn't be here, but handle gracefully
            _ => {}
        }

        changed
    }

    /// Replace a VReg in a MirValue if it's in the copy map
    fn replace_value(&self, val: &mut MirValue, copy_map: &HashMap<VReg, VReg>) -> bool {
        if let MirValue::VReg(vreg) = val {
            if let Some(&new_vreg) = copy_map.get(vreg) {
                *vreg = new_vreg;
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::BinOpKind;

    #[test]
    fn test_simple_copy_propagation() {
        // v0 = 42
        // v1 = v0       <- copy
        // v2 = v1 + 1   <- should become v0 + 1
        // return v2
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v1),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        let cfg = CFG::build(&func);
        let pass = CopyPropagation;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // The BinOp should now use v0 instead of v1
        match &func.block(bb0).instructions[2] {
            MirInst::BinOp {
                lhs: MirValue::VReg(vreg),
                ..
            } => {
                assert_eq!(*vreg, v0, "Should have propagated v1 -> v0");
            }
            _ => panic!("Expected BinOp"),
        }
    }

    #[test]
    fn test_transitive_copy_propagation() {
        // v0 = 42
        // v1 = v0
        // v2 = v1       <- transitive copy
        // v3 = v2 + 1   <- should become v0 + 1
        // return v3
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();
        let v3 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v2,
            src: MirValue::VReg(v1),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v3,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v2),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v3)),
        };

        let cfg = CFG::build(&func);
        let pass = CopyPropagation;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // The BinOp should now use v0 (resolved transitively through v2 -> v1 -> v0)
        match &func.block(bb0).instructions[3] {
            MirInst::BinOp {
                lhs: MirValue::VReg(vreg),
                ..
            } => {
                assert_eq!(*vreg, v0, "Should have transitively propagated v2 -> v0");
            }
            _ => panic!("Expected BinOp"),
        }
    }

    #[test]
    fn test_propagate_in_terminator() {
        // v0 = 1
        // v1 = v0
        // branch v1 -> bb1, bb2   <- should become branch v0
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v1,
            if_true: bb1,
            if_false: bb2,
        };

        func.block_mut(bb1).terminator = MirInst::Return {
            val: Some(MirValue::Const(1)),
        };
        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = CopyPropagation;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // The branch condition should now use v0
        match &func.block(bb0).terminator {
            MirInst::Branch { cond, .. } => {
                assert_eq!(*cond, v0, "Should have propagated v1 -> v0 in branch");
            }
            _ => panic!("Expected Branch"),
        }
    }

    #[test]
    fn test_no_propagation_needed() {
        // v0 = 42
        // return v0   <- no copies to propagate
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

        let cfg = CFG::build(&func);
        let pass = CopyPropagation;
        let changed = pass.run(&mut func, &cfg);

        assert!(!changed, "No vreg-to-vreg copies, so no changes");
    }

    #[test]
    fn test_multiple_uses_propagated() {
        // v0 = 42
        // v1 = v0
        // v2 = v1 + v1   <- both uses should be propagated
        // return v2
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v1),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        let cfg = CFG::build(&func);
        let pass = CopyPropagation;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // Both lhs and rhs should now use v0
        match &func.block(bb0).instructions[2] {
            MirInst::BinOp {
                lhs: MirValue::VReg(lhs_vreg),
                rhs: MirValue::VReg(rhs_vreg),
                ..
            } => {
                assert_eq!(*lhs_vreg, v0, "LHS should be propagated to v0");
                assert_eq!(*rhs_vreg, v0, "RHS should be propagated to v0");
            }
            _ => panic!("Expected BinOp with two VReg operands"),
        }
    }

    #[test]
    fn test_propagate_in_return() {
        // v0 = 42
        // v1 = v0
        // return v1   <- should become return v0
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

        let cfg = CFG::build(&func);
        let pass = CopyPropagation;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // Return should now use v0
        match &func.block(bb0).terminator {
            MirInst::Return {
                val: Some(MirValue::VReg(vreg)),
            } => {
                assert_eq!(*vreg, v0, "Return should use v0");
            }
            _ => panic!("Expected Return with VReg"),
        }
    }
}
