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
    ];
    for (requirement, key, description, minimum, source_suffix) in expected {
        assert_eq!(requirement.key(), key);
        assert_eq!(requirement.category(), "map-value-field");
        assert_eq!(requirement.description(), description);
        assert_eq!(requirement.minimum_kernel(), minimum);
        assert!(requirement.minimum_kernel_source().contains(source_suffix));
    }

    let requirements = [
        MapValueCompatibilityRequirement::BpfSpinLock,
        MapValueCompatibilityRequirement::BpfTimer,
        MapValueCompatibilityRequirement::BpfKptr,
        MapValueCompatibilityRequirement::BpfWorkqueue,
    ];
    assert_eq!(
        MapValueCompatibilityRequirement::effective_minimum_kernel(&requirements),
        Some("6.10")
    );
    assert!(MapValueCompatibilityRequirement::kernel_version_at_least(
        "6.10.0", "6.10"
    ));
    assert!(!MapValueCompatibilityRequirement::kernel_version_at_least(
        "6.9", "6.10"
    ));
}

#[test]
fn test_context_field_compatibility_requirements_are_source_backed() {
    let expected = [
        (CtxField::Pid, "pid", "4.2"),
        (CtxField::PacketLen, "packet_len", "4.1"),
        (CtxField::PktType, "pkt_type", "4.1"),
        (CtxField::QueueMapping, "queue_mapping", "4.1"),
        (CtxField::EthProtocol, "eth_protocol", "4.1"),
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
        (CtxField::RxQueueIndex, "rx_queue_index", "4.17"),
        (CtxField::FlowKeys, "flow_keys", "4.20"),
        (CtxField::Tstamp, "tstamp", "5.0"),
        (CtxField::WireLen, "wire_len", "5.0"),
        (CtxField::GsoSegs, "gso_segs", "5.1"),
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

    let sock_ops_data = ContextFieldCompatibilityRequirement::for_field_on_program(
        &CtxField::Data,
        Some(crate::compiler::EbpfProgramType::SockOps),
    )
    .expect("sock_ops ctx.data alias should be versioned");
    assert_eq!(sock_ops_data.minimum_kernel(), "5.10");

    assert!(
        ContextFieldCompatibilityRequirement::for_field(&CtxField::TracepointField(
            "pid".to_string()
        ))
        .is_none(),
        "fields without an independent source-checked floor should stay unversioned"
    );

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
    assert!(ContextFieldCompatibilityRequirement::kernel_version_at_least("6.2.0", "6.2"));
    assert!(!ContextFieldCompatibilityRequirement::kernel_version_at_least("6.1.99", "6.2"));
}
