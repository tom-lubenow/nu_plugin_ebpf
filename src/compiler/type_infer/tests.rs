use super::*;
use crate::compiler::mir::{AddressSpace, BlockId, MirFunction, RecordFieldDef, StackSlotKind};
use std::collections::HashMap;

mod advanced;
mod basics;
mod helpers;
mod kfuncs;

fn make_test_function() -> MirFunction {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;
    func
}
