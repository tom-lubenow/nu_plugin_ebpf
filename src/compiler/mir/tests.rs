use super::*;

#[test]
fn test_block_lookup_index_fast_path_and_fallback() {
    let mut func = MirFunction::new();
    let b0 = func.alloc_block();
    let b1 = func.alloc_block();

    assert_eq!(func.block(b1).id, b1);

    // Simulate non-index-stable ordering after block rewrites/removals.
    func.blocks.remove(0);

    assert!(!func.has_block(b0));
    assert!(func.has_block(b1));
    assert_eq!(func.block(b1).id, b1);
    func.block_mut(b1).terminator = MirInst::Return { val: None };
    assert!(matches!(func.block(b1).terminator, MirInst::Return { .. }));
}

#[test]
fn test_alloc_block_stays_unique_after_block_removal() {
    let mut func = MirFunction::new();
    let b0 = func.alloc_block();
    let b1 = func.alloc_block();

    func.blocks.remove(0);

    let b2 = func.alloc_block();
    assert_eq!(b2, BlockId(2));
    assert!(func.has_block(b1));
    assert!(func.has_block(b2));
    assert_ne!(b1, b2);
    assert!(!func.has_block(b0));
}

#[test]
fn test_map_kind_surface_classification() {
    for kind in [
        MapKind::Hash,
        MapKind::Array,
        MapKind::CgroupArray,
        MapKind::LpmTrie,
        MapKind::LruHash,
        MapKind::PerCpuHash,
        MapKind::PerCpuArray,
        MapKind::LruPerCpuHash,
        MapKind::PerfEventArray,
        MapKind::Queue,
        MapKind::Stack,
        MapKind::BloomFilter,
        MapKind::RingBuf,
        MapKind::StackTrace,
        MapKind::DevMap,
        MapKind::DevMapHash,
        MapKind::CpuMap,
        MapKind::XskMap,
        MapKind::SockMap,
        MapKind::SockHash,
        MapKind::SkStorage,
        MapKind::InodeStorage,
        MapKind::TaskStorage,
        MapKind::CgrpStorage,
        MapKind::ProgArray,
    ] {
        assert!(kind.supports_map_fd_materialization());
    }

    assert!(MapKind::Queue.is_queue_or_stack());
    assert!(MapKind::Stack.is_queue_or_stack());
    assert!(!MapKind::BloomFilter.is_queue_or_stack());

    assert!(MapKind::SockMap.is_socket_map());
    assert!(MapKind::SockHash.is_socket_map());
    assert!(!MapKind::Hash.is_socket_map());

    assert!(MapKind::SkStorage.is_local_storage());
    assert!(MapKind::InodeStorage.is_local_storage());
    assert!(MapKind::TaskStorage.is_local_storage());
    assert!(MapKind::CgrpStorage.is_local_storage());
    assert!(!MapKind::SockMap.is_local_storage());

    assert!(MapKind::DevMap.is_redirect_map());
    assert!(MapKind::DevMapHash.is_redirect_map());
    assert!(MapKind::CpuMap.is_redirect_map());
    assert!(MapKind::XskMap.is_redirect_map());
    assert!(!MapKind::SockMap.is_redirect_map());
}
