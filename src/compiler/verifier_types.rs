//! Flow-sensitive verifier-type analysis over MIR.
//!
//! This pass models a subset of the kernel verifier's type system, focusing on
//! pointer kinds and nullability. It is intended to reject uses that are known
//! to fail the verifier (e.g. dereferencing a map lookup result without a null check).

use std::collections::HashMap;

use super::instruction::{
    BpfHelper, HelperArgKind, HelperRetKind, HelperSignature, KfuncArgKind, KfuncRefKind,
    KfuncRetKind, KfuncSignature, helper_acquire_ref_kind, helper_release_ref_kind,
    kfunc_acquire_ref_kind, kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel as kfunc_pointer_arg_requires_kernel_shared,
    kfunc_release_ref_kind,
};
use super::mir::{
    AddressSpace, BinOpKind, BlockId, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME,
    KSTACK_MAP_NAME, MapKind, MapRef, MirFunction, MirInst, MirType, MirValue, RINGBUF_MAP_NAME,
    STRING_COUNTER_MAP_NAME, StackSlotId, TIMESTAMP_MAP_NAME, USTACK_MAP_NAME, VReg,
};

mod state;
use state::*;

mod apply;
mod calls;
mod driver;
mod map_layout;
mod ops;
mod ranges;
mod refinement;

use apply::{apply_inst, check_uses_initialized};
use calls::*;
pub use driver::verify_mir;
use map_layout::*;
use ops::*;
use ranges::*;
use refinement::*;

#[derive(Debug, Clone)]
pub struct VerifierTypeError {
    pub message: String,
}

impl VerifierTypeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VerifierTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifierTypeError {}

#[cfg(test)]
mod tests;
