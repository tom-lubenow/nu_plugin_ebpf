use super::*;
use crate::compiler::mir::{
    AddressSpace, BlockId, CtxField, MapKind, MapRef, MirFunction, MirInst, MirType, MirValue,
    STRING_COUNTER_MAP_NAME, StackSlotKind, StringAppendType,
};
use std::collections::HashMap;

mod core;
mod helpers;
mod kfuncs;
mod map_ops;
mod scalar_ranges;

fn verify_ok(func: &VccFunction) {
    VccVerifier::default()
        .verify_function(func)
        .expect("expected verifier success");
}

fn verify_err(func: &VccFunction, kind: VccErrorKind) {
    let err = VccVerifier::default()
        .verify_function(func)
        .expect_err("expected verifier error");
    assert!(
        err.iter().any(|e| e.kind == kind),
        "expected error {:?}, got {:?}",
        kind,
        err
    );
}

fn map_lookup_types(func: &MirFunction, vreg: VReg) -> HashMap<VReg, MirType> {
    let mut types = HashMap::new();
    for i in 0..func.vreg_count {
        types.insert(VReg(i), MirType::I64);
    }
    types.insert(
        vreg,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types
}

fn new_mir_function() -> (MirFunction, BlockId) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    (func, entry)
}
