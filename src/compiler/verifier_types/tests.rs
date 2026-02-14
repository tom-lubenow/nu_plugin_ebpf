use super::*;
use crate::compiler::mir::{
    COUNTER_MAP_NAME, MapKind, MapRef, MirType, STRING_COUNTER_MAP_NAME, StackSlotKind,
};

mod helper_refs;
mod helpers;
mod kfuncs;
mod map_ops;
mod pointer_ranges;

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
