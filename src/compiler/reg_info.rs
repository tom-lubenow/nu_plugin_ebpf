//! Register clobber information for MIR instructions.

use super::instruction::EbpfReg;
use super::mir::{MirInst, MirValue, StringAppendType};

const CALLER_SAVED: [EbpfReg; 5] = [
    EbpfReg::R1,
    EbpfReg::R2,
    EbpfReg::R3,
    EbpfReg::R4,
    EbpfReg::R5,
];
const SCRATCH_LIST_PUSH: [EbpfReg; 2] = [EbpfReg::R1, EbpfReg::R2];
const SCRATCH_LIST_GET: [EbpfReg; 1] = [EbpfReg::R1];
const SCRATCH_STRING_APPEND: [EbpfReg; 2] = [EbpfReg::R1, EbpfReg::R2];
const SCRATCH_STRING_APPEND_INT: [EbpfReg; 5] = [
    EbpfReg::R1,
    EbpfReg::R2,
    EbpfReg::R3,
    EbpfReg::R4,
    EbpfReg::R5,
];
const SCRATCH_INT_TO_STRING: [EbpfReg; 3] = [EbpfReg::R1, EbpfReg::R3, EbpfReg::R4];
const SCRATCH_HISTOGRAM: [EbpfReg; 2] = [EbpfReg::R1, EbpfReg::R2];

pub fn call_clobbers(inst: &MirInst) -> &'static [EbpfReg] {
    if matches!(
        inst,
        MirInst::CallHelper { .. }
            | MirInst::CallKfunc { .. }
            | MirInst::CallSubfn { .. }
            | MirInst::TailCall { .. }
            | MirInst::MapLookup { .. }
            | MirInst::MapUpdate { .. }
            | MirInst::MapDelete { .. }
            | MirInst::EmitEvent { .. }
            | MirInst::EmitRecord { .. }
            | MirInst::ReadStr { .. }
            | MirInst::Histogram { .. }
            | MirInst::StartTimer
            | MirInst::StopTimer { .. }
            | MirInst::LoadCtxField { .. }
    ) {
        &CALLER_SAVED
    } else {
        &[]
    }
}

pub fn scratch_clobbers(inst: &MirInst) -> &'static [EbpfReg] {
    match inst {
        MirInst::ListPush { .. } => &SCRATCH_LIST_PUSH,
        MirInst::ListGet {
            idx: MirValue::VReg(_),
            ..
        } => &SCRATCH_LIST_GET,
        MirInst::StringAppend { val_type, .. } => match val_type {
            StringAppendType::Integer => &SCRATCH_STRING_APPEND_INT,
            StringAppendType::Literal { .. } | StringAppendType::StringSlot { .. } => {
                &SCRATCH_STRING_APPEND
            }
        },
        MirInst::IntToString { .. } => &SCRATCH_INT_TO_STRING,
        MirInst::Histogram { .. } => &SCRATCH_HISTOGRAM,
        _ => &[],
    }
}
