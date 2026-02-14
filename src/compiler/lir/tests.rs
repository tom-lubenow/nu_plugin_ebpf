use super::*;

#[test]
fn test_block_lookup_index_fast_path_and_fallback() {
    let mut func = LirFunction::new();
    let b0 = func.alloc_block();
    let b1 = func.alloc_block();

    assert_eq!(func.block(b1).id, b1);

    // Simulate non-index-stable ordering after block rewrites/removals.
    func.blocks.remove(0);

    assert!(!func.has_block(b0));
    assert!(func.has_block(b1));
    assert_eq!(func.block(b1).id, b1);
    func.block_mut(b1).terminator = LirInst::Return { val: None };
    assert!(matches!(func.block(b1).terminator, LirInst::Return { .. }));
}
