use super::*;
use crate::compiler::mir::{MirInst, MirValue};

mod full_compilation;
mod integration;
mod manager_ssa;

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
