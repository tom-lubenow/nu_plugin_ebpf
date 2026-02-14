use super::*;
use crate::compiler::ir_to_mir::lower_ir_to_mir;
use crate::compiler::mir_to_lir::lower_mir_to_lir;
use nu_protocol::RegId;
use nu_protocol::ast::{Math, Operator};
use nu_protocol::ir::{Instruction, IrBlock, Literal};
use std::sync::Arc;

mod bpf_calls;
mod core_codegen;
mod maps_helpers;
mod strings_lists;

fn make_ir_block(instructions: Vec<Instruction>) -> IrBlock {
    IrBlock {
        instructions,
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 10,
        file_count: 0,
    }
}
