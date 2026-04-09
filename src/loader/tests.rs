use super::*;
use crate::compiler::mir::MapKind;
use crate::compiler::{
    CounterKeySchema, CounterKeySchemaField, EbpfObject, EbpfProgramType, MapRef, MirType,
};
use crate::kernel_btf::{KernelBtf, TrampolineValueKind};
use crate::program_spec::DEFAULT_PERF_EVENT_PERIOD;
use std::collections::HashMap;

#[test]
fn test_uprobe_target_basic() {
    let target = UprobeTarget::parse("/usr/bin/python:Py_Initialize").unwrap();
    assert_eq!(target.binary_path, "/usr/bin/python");
    assert_eq!(target.function_name, Some("Py_Initialize".to_string()));
    assert_eq!(target.offset, 0);
    assert_eq!(target.pid, None);
}

#[test]
fn test_uprobe_target_offset_hex() {
    let target = UprobeTarget::parse("/lib/libc.so.6:0x12345").unwrap();
    assert_eq!(target.binary_path, "/lib/libc.so.6");
    assert_eq!(target.function_name, None);
    assert_eq!(target.offset, 0x12345);
    assert_eq!(target.pid, None);
}

#[test]
fn test_uprobe_target_function_plus_offset() {
    let target = UprobeTarget::parse("/usr/bin/app:main+0x10").unwrap();
    assert_eq!(target.binary_path, "/usr/bin/app");
    assert_eq!(target.function_name, Some("main".to_string()));
    assert_eq!(target.offset, 0x10);
    assert_eq!(target.pid, None);
}

#[test]
fn test_uprobe_target_with_pid() {
    let target = UprobeTarget::parse("/usr/bin/python:Py_Initialize@1234").unwrap();
    assert_eq!(target.binary_path, "/usr/bin/python");
    assert_eq!(target.function_name, Some("Py_Initialize".to_string()));
    assert_eq!(target.offset, 0);
    assert_eq!(target.pid, Some(1234));
}

#[test]
fn test_uprobe_target_offset_with_pid() {
    let target = UprobeTarget::parse("/lib/libc.so.6:malloc+0x20@5678").unwrap();
    assert_eq!(target.binary_path, "/lib/libc.so.6");
    assert_eq!(target.function_name, Some("malloc".to_string()));
    assert_eq!(target.offset, 0x20);
    assert_eq!(target.pid, Some(5678));
}

#[test]
fn test_uprobe_target_invalid_no_colon() {
    let result = UprobeTarget::parse("/usr/bin/python");
    assert!(result.is_err());
}

#[test]
fn test_uprobe_target_invalid_empty_path() {
    let result = UprobeTarget::parse(":function");
    assert!(result.is_err());
}

#[test]
fn test_parse_probe_spec_uprobe() {
    let (prog_type, target) = parse_probe_spec("uprobe:/usr/bin/app:main").unwrap();
    assert!(matches!(prog_type, EbpfProgramType::Uprobe));
    assert_eq!(target, "/usr/bin/app:main");
}

#[test]
fn test_parse_program_spec_uprobe_is_structured() {
    let spec = parse_program_spec("uprobe:/usr/bin/app:main+0x10@123").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Uprobe {
            target: UprobeTarget {
                binary_path: "/usr/bin/app".to_string(),
                function_name: Some("main".to_string()),
                offset: 0x10,
                pid: Some(123),
            }
        }
    );
    assert_eq!(spec.to_string(), "uprobe:/usr/bin/app:main+0x10@123");
}

#[test]
fn test_parse_probe_spec_uretprobe() {
    let (prog_type, target) = parse_probe_spec("uretprobe:/lib/libc.so.6:malloc").unwrap();
    assert!(matches!(prog_type, EbpfProgramType::Uretprobe));
    assert_eq!(target, "/lib/libc.so.6:malloc");
}

#[test]
fn test_parse_probe_spec_fentry() {
    let result = parse_probe_spec("fentry:do_sys_openat2");

    match result {
        Ok((prog_type, target)) => {
            assert!(matches!(prog_type, EbpfProgramType::Fentry));
            assert_eq!(target, "do_sys_openat2");
        }
        Err(LoadError::NeedsSudo) => {}
        Err(LoadError::FunctionNotFound { .. }) => {}
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_parse_probe_spec_fexit() {
    let result = parse_probe_spec("fexit:do_sys_openat2");

    match result {
        Ok((prog_type, target)) => {
            assert!(matches!(prog_type, EbpfProgramType::Fexit));
            assert_eq!(target, "do_sys_openat2");
        }
        Err(LoadError::NeedsSudo) => {}
        Err(LoadError::FunctionNotFound { .. }) => {}
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_parse_probe_spec_raw_tracepoint_alias() {
    let (prog_type, target) = parse_probe_spec("raw_tp:sys_enter").unwrap();
    assert_eq!(prog_type, EbpfProgramType::RawTracepoint);
    assert_eq!(target, "sys_enter");
}

#[test]
fn test_parse_probe_spec_xdp() {
    let (prog_type, target) = parse_probe_spec("xdp:lo").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Xdp);
    assert_eq!(target, "lo");
}

#[test]
fn test_parse_probe_spec_perf_event() {
    let (prog_type, target) = parse_probe_spec("perf_event:software:cpu-clock").unwrap();
    assert_eq!(prog_type, EbpfProgramType::PerfEvent);
    assert_eq!(target, "software:cpu-clock");
}

#[test]
fn test_parse_program_spec_perf_event_is_structured() {
    let spec = parse_program_spec("perf_event:software:task-clock:cpu=0:pid=123:freq=99").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::PerfEvent {
            target: PerfEventTarget {
                event: PerfEventEvent::Software(PerfEventSoftwareEvent::TaskClock),
                cpu: Some(0),
                pid: Some(123),
                sample_policy: PerfEventSamplePolicy::Frequency(99),
            }
        }
    );
    assert_eq!(
        spec.to_string(),
        "perf_event:software:task-clock:cpu=0:pid=123:freq=99"
    );
}

#[test]
fn test_parse_program_spec_perf_event_page_faults_is_structured() {
    let spec = parse_program_spec("perf_event:software:page-faults:period=4096").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::PerfEvent {
            target: PerfEventTarget {
                event: PerfEventEvent::Software(PerfEventSoftwareEvent::PageFaults),
                cpu: None,
                pid: None,
                sample_policy: PerfEventSamplePolicy::Period(4096),
            }
        }
    );
    assert_eq!(
        spec.to_string(),
        "perf_event:software:page-faults:period=4096"
    );
}

#[test]
fn test_parse_program_spec_perf_event_hardware_is_structured() {
    let spec = parse_program_spec("perf_event:hardware:instructions:cpu=0:period=100000").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::PerfEvent {
            target: PerfEventTarget {
                event: PerfEventEvent::Hardware(PerfEventHardwareEvent::Instructions),
                cpu: Some(0),
                pid: None,
                sample_policy: PerfEventSamplePolicy::Period(100000),
            }
        }
    );
    assert_eq!(
        spec.to_string(),
        "perf_event:hardware:instructions:cpu=0:period=100000"
    );
}

#[test]
fn test_parse_program_spec_perf_event_pid_selector_is_structured() {
    let spec = parse_program_spec("perf_event:hardware:cpu-cycles:pid=456").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::PerfEvent {
            target: PerfEventTarget {
                event: PerfEventEvent::Hardware(PerfEventHardwareEvent::CpuCycles),
                cpu: None,
                pid: Some(456),
                sample_policy: PerfEventSamplePolicy::Period(DEFAULT_PERF_EVENT_PERIOD),
            }
        }
    );
    assert_eq!(spec.to_string(), "perf_event:hardware:cpu-cycles:pid=456");
}

#[test]
fn test_parse_probe_spec_tc_ingress() {
    let (prog_type, target) = parse_probe_spec("tc:lo:ingress").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Tc);
    assert_eq!(target, "lo:ingress");
}

#[test]
fn test_parse_program_spec_tc_is_structured() {
    let spec = parse_program_spec("tc:lo:ingress").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Tc {
            target: TcTarget {
                interface: "lo".to_string(),
                attach_type: aya::programs::TcAttachType::Ingress,
            }
        }
    );
    assert_eq!(spec.to_string(), "tc:lo:ingress");
}

#[test]
fn test_parse_probe_spec_cgroup_skb_egress() {
    let (prog_type, target) = parse_probe_spec("cgroup_skb:/sys/fs/cgroup:egress").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSkb);
    assert_eq!(target, "/sys/fs/cgroup:egress");
}

#[test]
fn test_parse_probe_spec_cgroup_sock_addr_connect4() {
    let (prog_type, target) = parse_probe_spec("cgroup_sock_addr:/sys/fs/cgroup:connect4").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSockAddr);
    assert_eq!(target, "/sys/fs/cgroup:connect4");
}

#[test]
fn test_parse_probe_spec_lsm_file_open() {
    let (prog_type, target) = parse_probe_spec("lsm:file_open").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Lsm);
    assert_eq!(target, "file_open");
}

#[test]
fn test_parse_program_spec_lsm_is_structured() {
    let spec = parse_program_spec("lsm:file_open").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Lsm {
            hook: "file_open".to_string(),
        }
    );
    assert_eq!(spec.to_string(), "lsm:file_open");
}

#[test]
fn test_parse_program_spec_cgroup_sock_addr_is_structured() {
    let spec = parse_program_spec("cgroup_sock_addr:/sys/fs/cgroup:connect4").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupSockAddr {
            target: CgroupSockAddrTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
                attach_type: aya::programs::CgroupSockAddrAttachType::Connect4,
            }
        }
    );
    assert_eq!(spec.to_string(), "cgroup_sock_addr:/sys/fs/cgroup:connect4");
}

#[test]
fn test_parse_probe_spec_rejects_unknown_tc_interface() {
    let err = parse_probe_spec("tc:__nu_plugin_ebpf_no_such_iface__:ingress")
        .expect_err("expected unknown tc interface error");
    assert!(matches!(err, LoadError::Load(msg) if msg.contains("Unknown network interface")));
}

#[test]
fn test_parse_probe_spec_rejects_invalid_tc_direction() {
    let err = parse_probe_spec("tc:lo:sideways").expect_err("expected invalid tc direction");
    assert!(matches!(err, LoadError::Load(msg) if msg.contains("Invalid tc attach direction")));
}

#[test]
fn test_parse_probe_spec_rejects_invalid_perf_event_selector() {
    let err = parse_probe_spec("perf_event:software:cpu-clock:mode=fast")
        .expect_err("expected invalid perf_event selector");
    assert!(
        matches!(err, LoadError::Load(msg) if msg.contains("Unrecognized perf_event selector"))
    );
}

#[test]
fn test_parse_probe_spec_rejects_offline_perf_event_cpu() {
    let err = parse_probe_spec("perf_event:software:cpu-clock:cpu=999999")
        .expect_err("expected offline perf_event cpu rejection");
    assert!(matches!(err, LoadError::Load(msg) if msg.contains("not currently online")));
}

#[test]
fn test_parse_probe_spec_rejects_invalid_cgroup_skb_direction() {
    let err = parse_probe_spec("cgroup_skb:/sys/fs/cgroup:sideways")
        .expect_err("expected invalid cgroup_skb direction");
    assert!(
        matches!(err, LoadError::Load(msg) if msg.contains("Invalid cgroup_skb attach direction"))
    );
}

#[test]
fn test_parse_probe_spec_rejects_unknown_cgroup_path() {
    let err = parse_probe_spec("cgroup_skb:/__nu_plugin_ebpf_missing_cgroup__:ingress")
        .expect_err("expected unknown cgroup path error");
    assert!(matches!(err, LoadError::Load(msg) if msg.contains("Unknown cgroup path")));
}

#[test]
fn test_parse_probe_spec_rejects_invalid_cgroup_sock_addr_attach_kind() {
    let err = parse_probe_spec("cgroup_sock_addr:/sys/fs/cgroup:sideways")
        .expect_err("expected invalid cgroup_sock_addr attach kind");
    assert!(
        matches!(err, LoadError::Load(msg) if msg.contains("Invalid cgroup_sock_addr attach kind"))
    );
}

#[test]
fn test_parse_probe_spec_rejects_unknown_xdp_interface() {
    let err = parse_probe_spec("xdp:__nu_plugin_ebpf_no_such_iface__")
        .expect_err("expected unknown interface error");
    assert!(matches!(err, LoadError::Load(msg) if msg.contains("Unknown network interface")));
}

#[test]
fn test_parse_probe_spec_rejects_unsupported_fexit_aggregate_return_target() {
    let candidate = ["__jump_label_patch", "__ioapic_read_entry"]
        .into_iter()
        .find(|func_name| {
            matches!(
                KernelBtf::get().function_trampoline_ret(func_name),
                Ok(Some(spec)) if matches!(spec.kind, TrampolineValueKind::Aggregate { .. })
            )
        });

    let Some(func_name) = candidate else {
        return;
    };

    match parse_probe_spec(&format!("fexit:{func_name}")) {
        Err(LoadError::UnsupportedTrampolineTarget {
            probe_type,
            target,
            reason,
        }) => {
            assert_eq!(probe_type, "fexit");
            assert_eq!(target, func_name);
            assert!(reason.contains("aggregate return"));
        }
        Err(LoadError::NeedsSudo) | Err(LoadError::FunctionNotFound { .. }) => {}
        other => panic!("Unexpected result: {:?}", other),
    }
}

#[test]
fn test_parse_probe_spec_kprobe_unchanged() {
    // This test may fail with NeedsSudo if running without root
    // That's expected - we're testing the parsing, not the permissions
    let result = parse_probe_spec("kprobe:sys_clone");

    match result {
        Ok((prog_type, target)) => {
            assert!(matches!(prog_type, EbpfProgramType::Kprobe));
            assert_eq!(target, "sys_clone");
        }
        Err(LoadError::NeedsSudo) => {
            // Expected when running tests without root - validation correctly detected
            // that we don't have permission to read the function list
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_merge_generic_map_value_types_drops_conflicts() {
    let shared = MapRef {
        name: "shared_path".to_string(),
        kind: MapKind::Hash,
    };
    let unique = MapRef {
        name: "other_map".to_string(),
        kind: MapKind::Hash,
    };
    let path_ty = MirType::Struct {
        name: Some("path".to_string()),
        kernel_btf_type_id: None,
        fields: vec![],
    };
    let other_ty = MirType::I64;
    let conflicting_ty = MirType::U64;

    let merged = EbpfState::merge_generic_map_value_types(
        [
            HashMap::from([
                (shared.clone(), path_ty.clone()),
                (unique.clone(), other_ty.clone()),
            ]),
            HashMap::from([(shared.clone(), path_ty.clone())]),
            HashMap::from([(shared.clone(), conflicting_ty)]),
        ]
        .iter(),
    );

    assert_eq!(merged.get(&unique), Some(&other_ty));
    assert!(!merged.contains_key(&shared));
}

#[test]
fn test_attach_with_pin_rejects_struct_ops_objects() {
    let state = EbpfState::new();
    let object = EbpfObject::struct_ops("demo", "file", vec![0; 8]).build();

    let err = state
        .attach_with_pin(&object, Some("shared"))
        .expect_err("struct_ops objects should reject pinned map sharing");

    assert!(
        matches!(err, LoadError::Load(msg) if msg.contains("do not yet support pinned map sharing"))
    );
}

#[test]
fn test_structured_event_string_respects_field_size() {
    let schema = EventSchema {
        fields: vec![
            crate::compiler::SchemaField {
                name: "msg".to_string(),
                field_type: BpfFieldType::String,
                value_schema: None,
                offset: 0,
                bitfield: None,
            },
            crate::compiler::SchemaField {
                name: "value".to_string(),
                field_type: BpfFieldType::Int {
                    size: 8,
                    signed: true,
                },
                value_schema: None,
                offset: 24,
                bitfield: None,
            },
        ],
        total_size: 32,
    };

    let msg_bytes: Vec<u8> = (0..24).map(|i| b'a' + (i % 26) as u8).collect();
    let mut buf = Vec::new();
    buf.extend_from_slice(&msg_bytes);
    buf.extend_from_slice(&0x0102030405060708i64.to_le_bytes());

    let data =
        EbpfState::deserialize_structured_event(&buf, &schema).expect("expected structured event");

    match data {
        BpfEventData::Record(fields) => {
            let mut msg = None;
            let mut value = None;
            for (name, field) in fields {
                match (name.as_str(), field) {
                    ("msg", BpfFieldValue::String(s)) => msg = Some(s),
                    ("value", BpfFieldValue::Int(v)) => value = Some(v),
                    _ => {}
                }
            }
            let expected_msg = String::from_utf8_lossy(&msg_bytes).to_string();
            assert_eq!(msg, Some(expected_msg));
            assert_eq!(value, Some(0x0102030405060708i64));
        }
        _ => panic!("expected structured record"),
    }
}

#[test]
fn test_structured_event_sized_scalar_fields_decode() {
    let schema = EventSchema {
        fields: vec![
            crate::compiler::SchemaField {
                name: "flag".to_string(),
                field_type: BpfFieldType::Int {
                    size: 1,
                    signed: false,
                },
                value_schema: None,
                offset: 0,
                bitfield: None,
            },
            crate::compiler::SchemaField {
                name: "delta".to_string(),
                field_type: BpfFieldType::Int {
                    size: 4,
                    signed: true,
                },
                value_schema: None,
                offset: 4,
                bitfield: None,
            },
        ],
        total_size: 8,
    };

    let mut buf = vec![0u8; 8];
    buf[0] = 0xff;
    buf[4..8].copy_from_slice(&(-2i32).to_le_bytes());

    let data =
        EbpfState::deserialize_structured_event(&buf, &schema).expect("expected structured event");

    match data {
        BpfEventData::Record(fields) => {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0], ("flag".to_string(), BpfFieldValue::Int(255)));
            assert_eq!(fields[1], ("delta".to_string(), BpfFieldValue::Int(-2)));
        }
        _ => panic!("expected structured record"),
    }
}

#[test]
fn test_structured_event_bytes_field_preserved() {
    let schema = EventSchema {
        fields: vec![crate::compiler::SchemaField {
            name: "raw".to_string(),
            field_type: BpfFieldType::Bytes(12),
            value_schema: None,
            offset: 0,
            bitfield: None,
        }],
        total_size: 12,
    };

    let buf: Vec<u8> = (0..12).map(|i| i as u8).collect();
    let data =
        EbpfState::deserialize_structured_event(&buf, &schema).expect("expected structured event");

    match data {
        BpfEventData::Record(fields) => {
            assert_eq!(fields.len(), 1);
            match &fields[0] {
                (name, BpfFieldValue::Bytes(bytes)) => {
                    assert_eq!(name, "raw");
                    assert_eq!(bytes, &buf);
                }
                other => panic!("expected bytes field, got {:?}", other),
            }
        }
        _ => panic!("expected structured record"),
    }
}

#[test]
fn test_structured_event_nested_record_and_array_schema_decode() {
    let schema = EventSchema {
        fields: vec![
            crate::compiler::SchemaField {
                name: "path".to_string(),
                field_type: BpfFieldType::Bytes(16),
                value_schema: Some(CounterKeySchema::Record {
                    name: Some("path".to_string()),
                    fields: vec![
                        CounterKeySchemaField {
                            name: "mnt".to_string(),
                            schema: CounterKeySchema::Int {
                                size: 8,
                                signed: false,
                            },
                            offset: 0,
                            bitfield: None,
                        },
                        CounterKeySchemaField {
                            name: "dentry".to_string(),
                            schema: CounterKeySchema::Int {
                                size: 8,
                                signed: false,
                            },
                            offset: 8,
                            bitfield: None,
                        },
                    ],
                    total_size: 16,
                }),
                offset: 0,
                bitfield: None,
            },
            crate::compiler::SchemaField {
                name: "bytes".to_string(),
                field_type: BpfFieldType::Bytes(4),
                value_schema: Some(CounterKeySchema::Array {
                    elem: Box::new(CounterKeySchema::Int {
                        size: 1,
                        signed: false,
                    }),
                    len: 4,
                }),
                offset: 16,
                bitfield: None,
            },
        ],
        total_size: 20,
    };

    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
    buf.extend_from_slice(&0x1112131415161718u64.to_le_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4]);

    let data =
        EbpfState::deserialize_structured_event(&buf, &schema).expect("expected structured event");

    match data {
        BpfEventData::Record(fields) => {
            assert_eq!(
                fields[0],
                (
                    "path".to_string(),
                    BpfFieldValue::Record(vec![
                        ("mnt".to_string(), BpfFieldValue::Int(0x0102030405060708)),
                        ("dentry".to_string(), BpfFieldValue::Int(0x1112131415161718)),
                    ])
                )
            );
            assert_eq!(
                fields[1],
                (
                    "bytes".to_string(),
                    BpfFieldValue::Array(vec![
                        BpfFieldValue::Int(1),
                        BpfFieldValue::Int(2),
                        BpfFieldValue::Int(3),
                        BpfFieldValue::Int(4),
                    ])
                )
            );
        }
        _ => panic!("expected structured record"),
    }
}

#[test]
fn test_bytes_counter_key_string_schema_decodes_string() {
    let schema = CounterKeySchema::String { size: 8 };
    let decoded = EbpfState::deserialize_bytes_counter_key(b"nu\x00shell", Some(&schema));

    assert_eq!(decoded, CounterKeyValue::String("nu".to_string()));
}

#[test]
fn test_bytes_counter_key_record_schema_decodes_record() {
    let schema = CounterKeySchema::Record {
        name: Some("task".to_string()),
        fields: vec![
            CounterKeySchemaField {
                name: "pid".to_string(),
                schema: CounterKeySchema::Int {
                    size: 8,
                    signed: true,
                },
                offset: 0,
                bitfield: None,
            },
            CounterKeySchemaField {
                name: "comm".to_string(),
                schema: CounterKeySchema::String { size: 8 },
                offset: 8,
                bitfield: None,
            },
        ],
        total_size: 16,
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(&42i64.to_le_bytes());
    buf.extend_from_slice(b"nu\x00\x00\x00\x00\x00\x00");

    let decoded = EbpfState::deserialize_bytes_counter_key(&buf, Some(&schema));

    assert_eq!(
        decoded,
        CounterKeyValue::Record(vec![
            ("pid".to_string(), CounterKeyValue::Int(42)),
            (
                "comm".to_string(),
                CounterKeyValue::String("nu".to_string())
            ),
        ])
    );
}

#[test]
fn test_bytes_counter_key_opaque_schema_preserves_binary() {
    let schema = CounterKeySchema::Bytes { size: 4 };
    let decoded = EbpfState::deserialize_bytes_counter_key(&[1, 2, 3, 4], Some(&schema));

    assert_eq!(decoded, CounterKeyValue::Bytes(vec![1, 2, 3, 4]));
}
