use super::*;
use std::collections::HashSet;

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
    let mut keys = HashSet::new();
    let mut aliases = HashSet::new();

    for kind in MapKind::all() {
        assert!(keys.insert(kind.key()), "duplicate map kind key {kind:?}");
        assert!(
            kind.aliases().contains(&kind.key()),
            "{kind:?} aliases must include canonical key '{}'",
            kind.key()
        );

        for alias in kind.aliases() {
            assert!(
                aliases.insert(*alias),
                "duplicate map kind alias '{alias}' for {kind:?}"
            );
            assert_eq!(
                MapKind::from_name(alias),
                Some(*kind),
                "map kind alias '{alias}' should resolve to {kind:?}"
            );
        }

        assert_eq!(
            kind.supports_map_fd_materialization(),
            !matches!(
                *kind,
                MapKind::ArrayOfMaps
                    | MapKind::HashOfMaps
                    | MapKind::DeprecatedCgroupStorage
                    | MapKind::DeprecatedPerCpuCgroupStorage
                    | MapKind::StructOps
                    | MapKind::Arena
            ),
            "{kind:?}"
        );
    }

    assert_eq!(MapKind::all().len(), 33);
    assert_eq!(MapKind::from_name("unknown-map-kind"), None);

    assert!(MapKind::Queue.is_queue_or_stack());
    assert!(MapKind::Stack.is_queue_or_stack());
    assert!(!MapKind::BloomFilter.is_queue_or_stack());

    assert!(MapKind::SockMap.is_socket_map());
    assert!(MapKind::SockHash.is_socket_map());
    assert!(!MapKind::ReuseportSockArray.is_socket_map());
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

    assert!(MapKind::Hash.supports_builtin_counter_map());
    assert!(MapKind::PerCpuHash.supports_builtin_counter_map());
    assert!(!MapKind::Array.supports_builtin_counter_map());

    assert!(MapKind::Array.is_array_index_map());
    assert!(MapKind::PerCpuArray.is_array_index_map());
    assert!(!MapKind::Hash.is_array_index_map());

    assert!(MapKind::Queue.is_keyless_map());
    assert!(MapKind::Stack.is_keyless_map());
    assert!(MapKind::BloomFilter.is_keyless_map());
    assert!(MapKind::RingBuf.is_keyless_map());
    assert!(MapKind::UserRingBuf.is_keyless_map());
    assert!(!MapKind::Array.is_keyless_map());
}

#[test]
fn test_map_kind_kernel_compatibility_metadata() {
    let expected = [
        (MapKind::Hash, "BPF_MAP_TYPE_HASH", "3.19"),
        (MapKind::Array, "BPF_MAP_TYPE_ARRAY", "3.19"),
        (MapKind::CgroupArray, "BPF_MAP_TYPE_CGROUP_ARRAY", "4.8"),
        (MapKind::LpmTrie, "BPF_MAP_TYPE_LPM_TRIE", "4.11"),
        (MapKind::LruHash, "BPF_MAP_TYPE_LRU_HASH", "4.10"),
        (MapKind::PerCpuHash, "BPF_MAP_TYPE_PERCPU_HASH", "4.6"),
        (MapKind::PerCpuArray, "BPF_MAP_TYPE_PERCPU_ARRAY", "4.6"),
        (
            MapKind::LruPerCpuHash,
            "BPF_MAP_TYPE_LRU_PERCPU_HASH",
            "4.10",
        ),
        (
            MapKind::PerfEventArray,
            "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
            "4.3",
        ),
        (MapKind::ArrayOfMaps, "BPF_MAP_TYPE_ARRAY_OF_MAPS", "4.12"),
        (MapKind::HashOfMaps, "BPF_MAP_TYPE_HASH_OF_MAPS", "4.12"),
        (
            MapKind::DeprecatedCgroupStorage,
            "BPF_MAP_TYPE_CGROUP_STORAGE",
            "4.19",
        ),
        (
            MapKind::DeprecatedPerCpuCgroupStorage,
            "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
            "4.20",
        ),
        (MapKind::Queue, "BPF_MAP_TYPE_QUEUE", "4.20"),
        (MapKind::Stack, "BPF_MAP_TYPE_STACK", "4.20"),
        (MapKind::BloomFilter, "BPF_MAP_TYPE_BLOOM_FILTER", "5.16"),
        (MapKind::RingBuf, "BPF_MAP_TYPE_RINGBUF", "5.8"),
        (MapKind::StructOps, "BPF_MAP_TYPE_STRUCT_OPS", "5.6"),
        (MapKind::UserRingBuf, "BPF_MAP_TYPE_USER_RINGBUF", "6.1"),
        (MapKind::Arena, "BPF_MAP_TYPE_ARENA", "6.9"),
        (MapKind::StackTrace, "BPF_MAP_TYPE_STACK_TRACE", "4.6"),
        (MapKind::DevMap, "BPF_MAP_TYPE_DEVMAP", "4.14"),
        (MapKind::DevMapHash, "BPF_MAP_TYPE_DEVMAP_HASH", "5.4"),
        (MapKind::CpuMap, "BPF_MAP_TYPE_CPUMAP", "4.15"),
        (MapKind::XskMap, "BPF_MAP_TYPE_XSKMAP", "4.18"),
        (MapKind::SockMap, "BPF_MAP_TYPE_SOCKMAP", "4.14"),
        (MapKind::SockHash, "BPF_MAP_TYPE_SOCKHASH", "4.18"),
        (
            MapKind::ReuseportSockArray,
            "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
            "4.19",
        ),
        (MapKind::SkStorage, "BPF_MAP_TYPE_SK_STORAGE", "5.2"),
        (MapKind::InodeStorage, "BPF_MAP_TYPE_INODE_STORAGE", "5.10"),
        (MapKind::TaskStorage, "BPF_MAP_TYPE_TASK_STORAGE", "5.11"),
        (MapKind::CgrpStorage, "BPF_MAP_TYPE_CGRP_STORAGE", "6.2"),
        (MapKind::ProgArray, "BPF_MAP_TYPE_PROG_ARRAY", "4.2"),
    ];
    let expected_kinds = expected
        .iter()
        .map(|(kind, _, _)| *kind)
        .collect::<HashSet<_>>();
    assert_eq!(expected.len(), MapKind::all().len());
    assert_eq!(expected_kinds.len(), MapKind::all().len());

    for kind in MapKind::all() {
        assert!(
            expected_kinds.contains(kind),
            "missing compatibility metadata assertion for {kind:?}"
        );
    }

    for (kind, kernel_type, minimum_kernel) in expected {
        let requirement = kind.compatibility_requirement();
        assert_eq!(kind.kernel_map_type_name(), kernel_type);
        assert_eq!(
            kind.compatibility_feature_key(),
            format!("map:{kernel_type}")
        );
        assert_eq!(kind.minimum_kernel(), minimum_kernel);
        assert_eq!(requirement.kind(), kind);
        assert_eq!(requirement.key(), format!("map:{kernel_type}"));
        assert_eq!(requirement.category(), "map-kind");
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(&format!("/v{minimum_kernel}/")),
            "source should point at the Linux tag where {kernel_type} first appears"
        );
        assert!(
            requirement
                .minimum_kernel_source()
                .ends_with("/include/uapi/linux/bpf.h")
        );
    }

    let requirements = [
        MapKind::Hash.compatibility_requirement(),
        MapKind::RingBuf.compatibility_requirement(),
        MapKind::UserRingBuf.compatibility_requirement(),
    ];
    assert_eq!(
        MapCompatibilityRequirement::effective_minimum_kernel(&requirements),
        Some("6.1")
    );
    assert!(
        MapCompatibilityRequirement::effective_minimum_kernel_source(&requirements)
            .is_some_and(|source| source.contains("/v6.1/include/uapi/linux/bpf.h"))
    );
    assert!(MapCompatibilityRequirement::kernel_version_at_least(
        "6.1.12", "6.1"
    ));
    assert!(!MapCompatibilityRequirement::kernel_version_at_least(
        "5.15", "6.1"
    ));
}

#[test]
fn test_map_value_compatibility_requirements_are_source_backed() {
    let expected = [
        (
            MapValueCompatibilityRequirement::BpfSpinLock,
            "map-value:bpf_spin_lock",
            "BPF map-value spin lock field support",
            "5.1",
            "/v5.1/include/uapi/linux/bpf.h",
        ),
        (
            MapValueCompatibilityRequirement::BpfTimer,
            "map-value:bpf_timer",
            "BPF map-value timer field support",
            "5.15",
            "/v5.15/include/uapi/linux/bpf.h",
        ),
        (
            MapValueCompatibilityRequirement::BpfKptr,
            "map-value:kptr",
            "BPF map-value kptr field support",
            "5.19",
            "/v5.19/kernel/bpf/verifier.c",
        ),
        (
            MapValueCompatibilityRequirement::BpfWorkqueue,
            "map-value:bpf_wq",
            "BPF map-value workqueue field support",
            "6.10",
            "/v6.10/include/linux/bpf.h",
        ),
        (
            MapValueCompatibilityRequirement::BpfRefcount,
            "map-value:bpf_refcount",
            "BPF map-value refcount field support",
            "6.4",
            "/v6.4/kernel/bpf/btf.c",
        ),
        (
            MapValueCompatibilityRequirement::BpfListHead,
            "map-value:bpf_list_head",
            "BPF map-value list head field support",
            "6.2",
            "/v6.2/kernel/bpf/btf.c",
        ),
        (
            MapValueCompatibilityRequirement::BpfListNode,
            "map-value:bpf_list_node",
            "BPF map-value list node field support",
            "6.2",
            "/v6.2/kernel/bpf/btf.c",
        ),
        (
            MapValueCompatibilityRequirement::BpfRbRoot,
            "map-value:bpf_rb_root",
            "BPF map-value rbtree root field support",
            "6.4",
            "/v6.4/kernel/bpf/btf.c",
        ),
        (
            MapValueCompatibilityRequirement::BpfRbNode,
            "map-value:bpf_rb_node",
            "BPF map-value rbtree node field support",
            "6.4",
            "/v6.4/kernel/bpf/btf.c",
        ),
    ];
    for (requirement, key, description, minimum, source_suffix) in expected {
        assert_eq!(requirement.key(), key);
        assert_eq!(requirement.category(), "map-value-field");
        assert_eq!(requirement.description(), description);
        assert_eq!(requirement.minimum_kernel(), minimum);
        assert!(requirement.minimum_kernel_source().contains(source_suffix));
    }

    assert_eq!(
        MapValueCompatibilityRequirement::effective_minimum_kernel(
            MapValueCompatibilityRequirement::all()
        ),
        Some("6.10")
    );
    assert!(
        MapValueCompatibilityRequirement::effective_minimum_kernel_source(
            MapValueCompatibilityRequirement::all()
        )
        .is_some_and(|source| source.contains("/v6.10/include/linux/bpf.h"))
    );
    assert!(MapValueCompatibilityRequirement::kernel_version_at_least(
        "6.10.0", "6.10"
    ));
    assert!(!MapValueCompatibilityRequirement::kernel_version_at_least(
        "6.9", "6.10"
    ));
}

#[test]
fn test_bpf_graph_root_wrappers_parse_contains_metadata() {
    let list_root = MirType::bpf_list_head_root_struct("node_data", "node");
    let list_info = list_root
        .bpf_graph_root_info()
        .expect("list root should carry graph metadata");
    assert_eq!(list_info.kind, BpfGraphRootKind::ListHead);
    assert_eq!(list_info.value_type, "node_data");
    assert_eq!(list_info.node_field, "node");
    assert!(list_info.object_type.is_none());
    assert_eq!(list_root.size(), 16);
    assert_eq!(list_root.align(), 8);
    assert!(list_root.is_bpf_list_head_struct());
    assert!(!list_root.is_bpf_rb_root_struct());

    let rb_root = MirType::bpf_rb_root_struct_with_contains("rb_node_data", "rb");
    let rb_info = rb_root
        .bpf_graph_root_info()
        .expect("rbtree root should carry graph metadata");
    assert_eq!(rb_info.kind, BpfGraphRootKind::RbRoot);
    assert_eq!(rb_info.value_type, "rb_node_data");
    assert_eq!(rb_info.node_field, "rb");
    assert!(rb_info.object_type.is_none());
    assert_eq!(rb_root.size(), 16);
    assert_eq!(rb_root.align(), 8);
    assert!(rb_root.is_bpf_rb_root_struct());
    assert!(!rb_root.is_bpf_list_head_struct());

    assert!(
        MirType::bpf_list_head_struct()
            .bpf_graph_root_info()
            .is_none(),
        "plain graph helper structs should not imply contains metadata"
    );
}

#[test]
fn test_bpf_graph_root_wrapper_can_carry_object_payload_schema() {
    let object_ty = MirType::Struct {
        name: Some("node_data".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "node".to_string(),
                ty: MirType::bpf_list_node_struct(),
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "cookie".to_string(),
                ty: MirType::U64,
                offset: 16,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let root =
        MirType::bpf_list_head_root_struct_with_object("node_data", "node", object_ty.clone());
    let info = root
        .bpf_graph_root_info()
        .expect("root should carry contains metadata");

    assert_eq!(info.kind, BpfGraphRootKind::ListHead);
    assert_eq!(info.value_type, "node_data");
    assert_eq!(info.node_field, "node");
    assert_eq!(info.object_type, Some(&object_ty));
    assert_eq!(root.size(), BpfGraphRootKind::ListHead.root_size());
    assert!(root.is_bpf_list_head_struct());
}

#[test]
fn test_verifier_managed_struct_sizes_follow_kernel_btf_when_available() {
    use crate::kernel_btf::KernelBtf;

    for (name, ty, fallback) in [
        ("bpf_timer", MirType::bpf_timer_struct(), 16),
        ("bpf_spin_lock", MirType::bpf_spin_lock_struct(), 4),
        ("bpf_res_spin_lock", MirType::bpf_res_spin_lock_struct(), 4),
        ("bpf_wq", MirType::bpf_wq_struct(), 16),
        ("bpf_refcount", MirType::bpf_refcount_struct(), 4),
        ("bpf_dynptr", MirType::bpf_dynptr_struct(), 16),
    ] {
        if let Ok(size) = KernelBtf::get().kernel_named_type_size_bytes(name) {
            assert_eq!(ty.size(), size, "{name} should use kernel BTF size");
        } else {
            assert_eq!(ty.size(), fallback, "{name} should use fallback size");
        }
    }

    let list_node_size = MirType::bpf_list_node_struct().size();
    let rb_node_size = MirType::bpf_rb_node_struct().size();
    assert_eq!(BpfGraphRootKind::ListHead.node_size(), list_node_size);
    assert_eq!(BpfGraphRootKind::RbRoot.node_size(), rb_node_size);

    if let Ok(size) = KernelBtf::get().kernel_named_type_size_bytes("bpf_list_node") {
        assert_eq!(list_node_size, size);
    } else {
        assert_eq!(list_node_size, 16);
    }
    if let Ok(size) = KernelBtf::get().kernel_named_type_size_bytes("bpf_rb_node") {
        assert_eq!(rb_node_size, size);
    } else {
        assert_eq!(rb_node_size, 24);
    }
}

#[test]
fn test_context_field_compatibility_requirements_are_source_backed() {
    let expected = [
        (CtxField::Pid, "pid", "4.2"),
        (CtxField::PacketLen, "packet_len", "4.1"),
        (CtxField::PktType, "pkt_type", "4.1"),
        (CtxField::QueueMapping, "queue_mapping", "4.1"),
        (CtxField::EthProtocol, "eth_protocol", "4.1"),
        (CtxField::Protocol, "protocol", "4.1"),
        (CtxField::VlanPresent, "vlan_present", "4.1"),
        (CtxField::VlanTci, "vlan_tci", "4.1"),
        (CtxField::VlanProto, "vlan_proto", "4.1"),
        (CtxField::SockMark, "mark", "4.1"),
        (CtxField::SockPriority, "priority", "4.1"),
        (CtxField::IngressIfindex, "ingress_ifindex", "4.7"),
        (CtxField::Ifindex, "ifindex", "4.7"),
        (CtxField::TcIndex, "tc_index", "4.7"),
        (CtxField::SkbHash, "hash", "4.7"),
        (CtxField::SkbCb, "cb", "4.7"),
        (CtxField::TcClassid, "tc_classid", "4.7"),
        (CtxField::Data, "data", "4.7"),
        (CtxField::DataEnd, "data_end", "4.7"),
        (CtxField::NapiId, "napi_id", "4.14"),
        (CtxField::Family, "family", "4.14"),
        (CtxField::RemoteIp4, "remote_ip4", "4.14"),
        (CtxField::RemoteIp6, "remote_ip6", "4.14"),
        (CtxField::RemotePort, "remote_port", "4.14"),
        (CtxField::LocalIp4, "local_ip4", "4.14"),
        (CtxField::LocalIp6, "local_ip6", "4.14"),
        (CtxField::LocalPort, "local_port", "4.14"),
        (CtxField::DataMeta, "data_meta", "4.15"),
        (CtxField::DeviceAccessType, "access_type", "4.15"),
        (CtxField::DeviceAccess, "device_access", "4.15"),
        (CtxField::DeviceType, "device_type", "4.15"),
        (CtxField::DeviceMajor, "major", "4.15"),
        (CtxField::DeviceMinor, "minor", "4.15"),
        (CtxField::UserFamily, "user_family", "4.17"),
        (CtxField::UserIp4, "user_ip4", "4.17"),
        (CtxField::UserIp6, "user_ip6", "4.17"),
        (CtxField::UserPort, "user_port", "4.17"),
        (CtxField::RxQueueIndex, "rx_queue_index", "4.16"),
        (CtxField::MsgSrcIp4, "msg_src_ip4", "4.18"),
        (CtxField::MsgSrcIp6, "msg_src_ip6", "4.18"),
        (CtxField::LircSample, "sample", "4.18"),
        (CtxField::LircValue, "value", "4.18"),
        (CtxField::LircMode, "mode", "4.18"),
        (CtxField::PerfSamplePeriod, "sample_period", "4.9"),
        (CtxField::PerfAddr, "addr", "5.0"),
        (CtxField::FlowKeys, "flow_keys", "4.20"),
        (CtxField::Tstamp, "tstamp", "5.0"),
        (CtxField::WireLen, "wire_len", "5.0"),
        (CtxField::GsoSegs, "gso_segs", "5.1"),
        (CtxField::SysctlWrite, "write", "5.2"),
        (CtxField::SysctlFilePos, "file_pos", "5.2"),
        (CtxField::SockoptLevel, "level", "5.3"),
        (CtxField::SockoptOptname, "optname", "5.3"),
        (CtxField::SockoptOptlen, "optlen", "5.3"),
        (CtxField::SockoptOptval, "optval", "5.3"),
        (CtxField::SockoptOptvalEnd, "optval_end", "5.3"),
        (CtxField::SockoptRetval, "sockopt_retval", "5.3"),
        (CtxField::GsoSize, "gso_size", "5.7"),
        (CtxField::EgressIfindex, "egress_ifindex", "5.8"),
        (CtxField::SockOpsSkbLen, "skb_len", "5.10"),
        (CtxField::SockOpsSkbTcpFlags, "skb_tcp_flags", "5.10"),
        (CtxField::Hwtstamp, "hwtstamp", "5.16"),
        (CtxField::TstampType, "tstamp_type", "5.18"),
        (CtxField::SockOpsSkbHwtstamp, "skb_hwtstamp", "6.2"),
        (CtxField::NetfilterState, "state", "6.4"),
        (CtxField::NetfilterSkb, "skb", "6.4"),
        (CtxField::NetfilterHook, "hook", "6.4"),
        (CtxField::NetfilterProtocolFamily, "pf", "6.4"),
    ];

    for (field, field_name, minimum_kernel) in expected {
        let requirement = ContextFieldCompatibilityRequirement::for_field(&field)
            .unwrap_or_else(|| panic!("expected ctx.{field_name} to be versioned"));
        assert_eq!(requirement.field(), &field);
        assert_eq!(requirement.key(), format!("ctx:{field_name}"));
        assert_eq!(requirement.category(), "context-field");
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(&format!("/v{minimum_kernel}/")),
            "source should point at the Linux tag where ctx.{field_name} first appears"
        );
    }

    let generic_packet_len = ContextFieldCompatibilityRequirement::for_field(&CtxField::PacketLen)
        .expect("generic ctx.packet_len should remain versioned");
    assert_eq!(generic_packet_len.minimum_kernel(), "4.1");

    let xdp_packet_len = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::PacketLen,
        Some(crate::compiler::EbpfProgramType::Xdp),
    )
    .expect("xdp ctx.packet_len should inherit the xdp_md data floor");
    assert_eq!(xdp_packet_len.minimum_kernel(), "4.8");

    let sock_ops_packet_len = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::PacketLen,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.packet_len alias should be versioned");
    assert_eq!(sock_ops_packet_len.minimum_kernel(), "5.10");
    assert!(
        sock_ops_packet_len
            .minimum_kernel_source()
            .contains("/v5.10/")
    );

    let generic_data = ContextFieldCompatibilityRequirement::for_field(&CtxField::Data)
        .expect("generic ctx.data should remain versioned");
    assert_eq!(generic_data.minimum_kernel(), "4.7");

    let xdp_data = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Data,
        Some(crate::compiler::EbpfProgramType::Xdp),
    )
    .expect("xdp ctx.data should use the xdp_md field floor");
    assert_eq!(xdp_data.minimum_kernel(), "4.8");

    let xdp_ingress_ifindex = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::IngressIfindex,
        Some(crate::compiler::EbpfProgramType::Xdp),
    )
    .expect("xdp ctx.ingress_ifindex should use the xdp_md field floor");
    assert_eq!(xdp_ingress_ifindex.minimum_kernel(), "4.16");

    let xdp_rx_queue_index = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::RxQueueIndex,
        Some(crate::compiler::EbpfProgramType::Xdp),
    )
    .expect("xdp ctx.rx_queue_index should use the xdp_md field floor");
    assert_eq!(xdp_rx_queue_index.minimum_kernel(), "4.16");

    let sock_ops_data = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Data,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.data alias should be versioned");
    assert_eq!(sock_ops_data.minimum_kernel(), "5.10");

    let cgroup_sock_addr_family = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Family,
        Some(crate::compiler::EbpfProgramType::CgroupSockAddr),
    )
    .expect("cgroup_sock_addr ctx.family should be target-versioned");
    assert_eq!(cgroup_sock_addr_family.minimum_kernel(), "4.17");

    let cgroup_sock_family = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Family,
        Some(crate::compiler::EbpfProgramType::CgroupSock),
    )
    .expect("cgroup_sock ctx.family should be target-versioned");
    assert_eq!(cgroup_sock_family.minimum_kernel(), "4.10");

    let cgroup_sock_protocol = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Protocol,
        Some(crate::compiler::EbpfProgramType::CgroupSock),
    )
    .expect("cgroup_sock ctx.protocol should use bpf_sock field floor");
    assert_eq!(cgroup_sock_protocol.minimum_kernel(), "4.10");

    let lwt_protocol = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Protocol,
        Some(crate::compiler::EbpfProgramType::LwtXmit),
    )
    .expect("lwt_xmit ctx.protocol should use skb protocol field floor");
    assert_eq!(lwt_protocol.key(), "ctx:protocol");
    assert_eq!(lwt_protocol.minimum_kernel(), "4.1");

    let cgroup_sock_mark = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SockMark,
        Some(crate::compiler::EbpfProgramType::CgroupSock),
    )
    .expect("cgroup_sock ctx.mark should use bpf_sock field floor");
    assert_eq!(cgroup_sock_mark.minimum_kernel(), "4.14");

    let cgroup_sock_remote_port = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::RemotePort,
        Some(crate::compiler::EbpfProgramType::CgroupSock),
    )
    .expect("cgroup_sock ctx.remote_port should use bpf_sock dst field floor");
    assert_eq!(cgroup_sock_remote_port.minimum_kernel(), "5.1");

    let cgroup_sock_rx_queue = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SockRxQueueMapping,
        Some(crate::compiler::EbpfProgramType::CgroupSock),
    )
    .expect("cgroup_sock ctx.rx_queue_mapping should use bpf_sock field floor");
    assert_eq!(cgroup_sock_rx_queue.minimum_kernel(), "5.8");
    let generic_sock_rx_queue =
        ContextFieldCompatibilityRequirement::for_field(&CtxField::SockRxQueueMapping)
            .expect("bpf_sock rx_queue_mapping projection should have a source-backed floor");
    assert_eq!(generic_sock_rx_queue.minimum_kernel(), "5.8");

    let sk_lookup_family = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Family,
        Some(crate::compiler::EbpfProgramType::SkLookup),
    )
    .expect("sk_lookup ctx.family should use bpf_sk_lookup field floor");
    assert_eq!(sk_lookup_family.minimum_kernel(), "5.9");

    let sk_lookup_cookie = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::LookupCookie,
        Some(crate::compiler::EbpfProgramType::SkLookup),
    )
    .expect("sk_lookup ctx.cookie should use bpf_sk_lookup cookie floor");
    assert_eq!(sk_lookup_cookie.minimum_kernel(), "5.13");

    let sk_lookup_ingress_ifindex = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::IngressIfindex,
        Some(crate::compiler::EbpfProgramType::SkLookup),
    )
    .expect("sk_lookup ctx.ingress_ifindex should use bpf_sk_lookup field floor");
    assert_eq!(sk_lookup_ingress_ifindex.minimum_kernel(), "5.17");
    assert!(
        sk_lookup_ingress_ifindex
            .minimum_kernel_source()
            .contains("/v5.17/include/uapi/linux/bpf.h")
    );

    let sk_msg_data = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Data,
        Some(crate::compiler::EbpfProgramType::SkMsg),
    )
    .expect("sk_msg ctx.data should use sk_msg_md field floor");
    assert_eq!(sk_msg_data.minimum_kernel(), "4.17");

    let sk_msg_family = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Family,
        Some(crate::compiler::EbpfProgramType::SkMsg),
    )
    .expect("sk_msg ctx.family should use sk_msg_md field floor");
    assert_eq!(sk_msg_family.minimum_kernel(), "4.18");

    let sk_msg_size = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::PacketLen,
        Some(crate::compiler::EbpfProgramType::SkMsg),
    )
    .expect("sk_msg ctx.size should use sk_msg_md size floor");
    assert_eq!(sk_msg_size.minimum_kernel(), "5.0");

    let sk_msg_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::SkMsg),
    )
    .expect("sk_msg ctx.sk should use sk_msg_md socket floor");
    assert_eq!(sk_msg_socket.minimum_kernel(), "5.8");

    let sk_skb_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::SkSkb),
    )
    .expect("sk_skb ctx.sk should use __sk_buff socket floor");
    assert_eq!(sk_skb_socket.minimum_kernel(), "5.1");

    let sk_skb_parser_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::SkSkbParser),
    )
    .expect("sk_skb_parser ctx.sk should use __sk_buff socket floor");
    assert_eq!(sk_skb_parser_socket.minimum_kernel(), "5.1");

    let sk_reuseport_hash = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SkbHash,
        Some(crate::compiler::EbpfProgramType::SkReuseport),
    )
    .expect("sk_reuseport ctx.hash should use sk_reuseport_md base floor");
    assert_eq!(sk_reuseport_hash.minimum_kernel(), "4.19");

    let sk_reuseport_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::SkReuseport),
    )
    .expect("sk_reuseport ctx.sk should use sk_reuseport_md socket floor");
    assert_eq!(sk_reuseport_socket.minimum_kernel(), "5.14");

    let sk_reuseport_migrating_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::MigratingSocket,
        Some(crate::compiler::EbpfProgramType::SkReuseport),
    )
    .expect("sk_reuseport ctx.migrating_sk should use sk_reuseport_md socket floor");
    assert_eq!(sk_reuseport_migrating_socket.minimum_kernel(), "5.14");

    let sock_ops_op = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SockOp,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.op should use bpf_sock_ops base floor");
    assert_eq!(sock_ops_op.minimum_kernel(), "4.14");

    for field in [CtxField::SockOpsReply, CtxField::SockOpsReplyLong] {
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program(
            &field,
            Some(crate::compiler::EbpfProgramType::SockOps),
        )
        .unwrap_or_else(|| {
            panic!(
                "sock_ops ctx.{} should use bpf_sock_ops base floor",
                field.display_name()
            )
        });
        assert_eq!(requirement.minimum_kernel(), "4.14");
    }

    let sock_ops_args = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SockOpsArgs,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.args should use bpf_sock_ops v4.16 floor");
    assert_eq!(sock_ops_args.minimum_kernel(), "4.16");

    let sock_ops_state = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SockState,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.state should use bpf_sock_ops v4.16 floor");
    assert_eq!(sock_ops_state.minimum_kernel(), "4.16");

    let sock_ops_bytes_acked = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::SockOpsBytesAcked,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.bytes_acked should use bpf_sock_ops v4.16 floor");
    assert_eq!(sock_ops_bytes_acked.minimum_kernel(), "4.16");

    let sock_ops_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.sk should use bpf_sock_ops socket floor");
    assert_eq!(sock_ops_socket.minimum_kernel(), "5.3");

    let sk_lookup_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::SkLookup),
    )
    .expect("sk_lookup ctx.sk should use bpf_sk_lookup socket floor");
    assert_eq!(sk_lookup_socket.minimum_kernel(), "5.9");

    let cgroup_sock_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::CgroupSock),
    )
    .expect("cgroup_sock ctx.sk should use raw bpf_sock context floor");
    assert_eq!(cgroup_sock_socket.minimum_kernel(), "4.10");

    let cgroup_sock_addr_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::CgroupSockAddr),
    )
    .expect("cgroup_sock_addr ctx.sk should use bpf_sock_addr socket floor");
    assert_eq!(cgroup_sock_addr_socket.minimum_kernel(), "5.3");

    let tc_socket = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Socket,
        Some(crate::compiler::EbpfProgramType::TcAction),
    )
    .expect("tc_action ctx.sk should use __sk_buff socket floor");
    assert_eq!(tc_socket.minimum_kernel(), "5.1");

    assert!(
        ContextFieldCompatibilityRequirement::for_field(&CtxField::RetVal).is_none(),
        "ctx.retval needs a target/program family to report an honest floor"
    );
    let kretprobe_retval = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::RetVal,
        Some(crate::compiler::EbpfProgramType::Kretprobe),
    )
    .expect("kretprobe ctx.retval should use the pt_regs return-value floor");
    assert_eq!(kretprobe_retval.key(), "ctx:retval");
    assert_eq!(kretprobe_retval.minimum_kernel(), "4.1");
    assert!(
        kretprobe_retval
            .minimum_kernel_source()
            .contains("/v4.1/include/uapi/linux/bpf.h")
    );
    let fexit_retval = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::RetVal,
        Some(crate::compiler::EbpfProgramType::Fexit),
    )
    .expect("fexit ctx.retval should use the BPF tracing return-value floor");
    assert_eq!(fexit_retval.key(), "ctx:retval");
    assert_eq!(fexit_retval.minimum_kernel(), "5.5");
    assert!(
        fexit_retval
            .minimum_kernel_source()
            .contains("/v5.5/include/uapi/linux/bpf.h")
    );

    for (field, minimum_kernel, source_fragment) in [
        (CtxField::IterMeta, "5.8", "/v5.8/include/linux/bpf.h"),
        (CtxField::IterTask, "5.8", "/v5.8/kernel/bpf/task_iter.c"),
        (CtxField::IterVma, "5.12", "/v5.12/kernel/bpf/task_iter.c"),
        (
            CtxField::IterCgroup,
            "6.1",
            "/v6.1/kernel/bpf/cgroup_iter.c",
        ),
        (CtxField::IterLink, "5.19", "/v5.19/kernel/bpf/link_iter.c"),
        (CtxField::IterUnixSk, "5.15", "/v5.15/net/unix/af_unix.c"),
        (CtxField::IterKsym, "6.0", "/v6.0/kernel/kallsyms.c"),
        (
            CtxField::IterKmemCache,
            "6.13",
            "/v6.13/kernel/bpf/kmem_cache_iter.c",
        ),
        (
            CtxField::IterDmabuf,
            "6.16",
            "/v6.16/kernel/bpf/dmabuf_iter.c",
        ),
    ] {
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program(
            &field,
            Some(crate::compiler::EbpfProgramType::Iter),
        )
        .unwrap_or_else(|| {
            panic!(
                "{} should have an iterator field floor",
                field.display_name()
            )
        });
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(source_fragment),
            "{} should point at {}",
            field.display_name(),
            source_fragment
        );
    }

    for (field, target, minimum_kernel, source_fragment) in [
        (
            CtxField::IterTask,
            "task_vma",
            "5.12",
            "/v5.12/kernel/bpf/task_iter.c",
        ),
        (
            CtxField::IterMapKey,
            "sockmap",
            "5.10",
            "/v5.10/net/core/sock_map.c",
        ),
        (
            CtxField::IterUid,
            "unix",
            "5.15",
            "/v5.15/net/unix/af_unix.c",
        ),
    ] {
        let requirement = ContextFieldCompatibilityRequirement::for_field_on_program_target(
            &field,
            Some(crate::compiler::EbpfProgramType::Iter),
            Some(target),
        )
        .unwrap_or_else(|| {
            panic!(
                "{} on iter:{} should have a target-aware field floor",
                field.display_name(),
                target
            )
        });
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(source_fragment),
            "{} on iter:{} should point at {}",
            field.display_name(),
            target,
            source_fragment
        );
    }

    assert!(
        ContextFieldCompatibilityRequirement::for_field(&CtxField::TracepointField(
            "pid".to_string()
        ))
        .is_none(),
        "tracepoint fields without a target should stay unversioned"
    );
    let openat_spec =
        crate::program_spec::ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
            .expect("tracepoint spec should parse");
    let filename_requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::TracepointField("filename".to_string()),
        &openat_spec,
    )
    .expect("known syscall tracepoint fields should report a target-specific floor");
    assert_eq!(
        filename_requirement.key(),
        "tracepoint:syscalls/sys_enter_openat:field:filename"
    );
    assert_eq!(filename_requirement.minimum_kernel(), "4.7");
    assert!(
        filename_requirement
            .minimum_kernel_source()
            .contains("include/trace/events/syscalls.h")
    );
    let args_requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::TracepointField("args".to_string()),
        &openat_spec,
    )
    .expect("known syscall tracepoint args field should report a fallback floor");
    assert_eq!(
        args_requirement.key(),
        "tracepoint:syscalls/sys_enter_openat:field:args"
    );
    assert_eq!(args_requirement.minimum_kernel(), "4.7");
    assert!(
        args_requirement
            .minimum_kernel_source()
            .contains("include/trace/events/syscalls.h")
    );
    let exit_openat2_spec =
        crate::program_spec::ProgramSpec::parse("tracepoint:syscalls/sys_exit_openat2")
            .expect("tracepoint spec should parse");
    let ret_requirement = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::TracepointField("ret".to_string()),
        &exit_openat2_spec,
    )
    .expect("known syscall exit tracepoint ret field should report a fallback floor");
    assert_eq!(
        ret_requirement.key(),
        "tracepoint:syscalls/sys_exit_openat2:field:ret"
    );
    assert_eq!(ret_requirement.minimum_kernel(), "5.6");
    assert!(
        ret_requirement
            .minimum_kernel_source()
            .contains("/v5.6/fs/open.c")
    );
    assert!(
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(
            &CtxField::TracepointField("__missing".to_string()),
            &openat_spec,
        )
        .is_none(),
        "unresolved or unversioned tracepoint payload fields should stay explicit"
    );

    let sendmsg4_spec =
        crate::program_spec::ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg4")
            .expect("sendmsg4 spec should parse");
    let sendmsg4_local_ip4 = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::LocalIp4,
        &sendmsg4_spec,
    )
    .expect("sendmsg4 ctx.local_ip4 should report a compatibility floor");
    assert_eq!(sendmsg4_local_ip4.key(), "ctx:local_ip4");
    assert_eq!(sendmsg4_local_ip4.minimum_kernel(), "4.18");
    assert!(
        sendmsg4_local_ip4
            .minimum_kernel_source()
            .contains("/v4.18/include/uapi/linux/bpf.h")
    );

    let sendmsg6_spec =
        crate::program_spec::ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg6")
            .expect("sendmsg6 spec should parse");
    let sendmsg6_local_ip6 = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::LocalIp6,
        &sendmsg6_spec,
    )
    .expect("sendmsg6 ctx.local_ip6 should report a compatibility floor");
    assert_eq!(sendmsg6_local_ip6.key(), "ctx:local_ip6");
    assert_eq!(sendmsg6_local_ip6.minimum_kernel(), "4.18");
    assert!(
        sendmsg6_local_ip6
            .minimum_kernel_source()
            .contains("/v4.18/include/uapi/linux/bpf.h")
    );

    let bind6_spec =
        crate::program_spec::ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:bind6")
            .expect("bind6 spec should parse");
    let bind6_local_ip6 = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::LocalIp6,
        &bind6_spec,
    )
    .expect("bind6 ctx.local_ip6 should report a compatibility floor");
    assert_eq!(bind6_local_ip6.key(), "ctx:local_ip6");
    assert_eq!(bind6_local_ip6.minimum_kernel(), "4.17");

    let requirements = [
        ContextFieldCompatibilityRequirement::for_field(&CtxField::Pid)
            .expect("pid should inherit a helper-backed floor"),
        ContextFieldCompatibilityRequirement::for_field(&CtxField::EgressIfindex)
            .expect("egress_ifindex should have a direct field floor"),
        ContextFieldCompatibilityRequirement::for_field(&CtxField::SockOpsSkbHwtstamp)
            .expect("skb_hwtstamp should have a direct sock_ops field floor"),
    ];
    assert_eq!(
        ContextFieldCompatibilityRequirement::effective_minimum_kernel(&requirements),
        Some("6.2")
    );
    assert!(
        ContextFieldCompatibilityRequirement::effective_minimum_kernel_source(&requirements)
            .is_some_and(|source| source.contains("/v6.2/include/uapi/linux/bpf.h"))
    );
    assert!(ContextFieldCompatibilityRequirement::kernel_version_at_least("6.2.0", "6.2"));
    assert!(!ContextFieldCompatibilityRequirement::kernel_version_at_least("6.1.99", "6.2"));
}
