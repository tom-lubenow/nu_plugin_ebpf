
use super::*;
use nu_protocol::DeclId;
use nu_protocol::RegId;
use nu_protocol::ir::{DataSlice, Instruction};
use std::sync::Arc;

#[test]
fn test_hir_call_args_folded() {
    let data: Arc<[u8]> = Arc::from(b"emit".as_slice());
    let ir = IrBlock {
        instructions: vec![
            Instruction::PushFlag {
                name: DataSlice { start: 0, len: 4 },
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let hir = HirFunction::from_ir_block(ir).unwrap();
    let block = &hir.blocks[0];
    match &block.stmts[0] {
        HirStmt::Call { args, .. } => {
            assert_eq!(args.flags.len(), 1);
            assert_eq!(args.flags[0], b"emit");
        }
        _ => panic!("Expected Call with folded args"),
    }
}
