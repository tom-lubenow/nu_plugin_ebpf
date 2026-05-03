use super::attach::{
    kernel_context_field_minimum_requirement_detail, kernel_global_minimum_requirement_detail,
    kernel_helper_minimum_requirement_detail, kernel_kfunc_minimum_requirement_detail,
    kernel_map_minimum_requirement_detail, kernel_map_value_minimum_requirement_detail,
    kernel_minimum_requirement_detail,
};
use super::*;
use crate::compiler::mir::{CtxField, MapKind};
use crate::compiler::{
    BpfHelper, ContextFieldCompatibilityRequirement, CounterKeySchema, CounterKeySchemaField,
    EbpfObject, EbpfProgram, EbpfProgramType, GlobalCompatibilityRequirement,
    KfuncCompatibilityRequirement, MapRef, MapValueCompatibilityRequirement, MirType,
    ProgramCompatibilityRequirement, ir_to_mir::AnnotatedValueSemantics,
};
use crate::kernel_btf::{KernelBtf, TrampolineValueKind};
use crate::program_spec::{
    CgroupSockAddrAttachKind, CgroupSysctlTarget, DEFAULT_PERF_EVENT_PERIOD, UprobeMultiTarget,
    XdpAttachMode, XdpTarget,
};
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
            },
            sleepable: false,
        }
    );
    assert_eq!(spec.to_string(), "uprobe:/usr/bin/app:main+0x10@123");
}

#[test]
fn test_parse_program_spec_sleepable_uprobes() {
    let (prog_type, target) = parse_probe_spec("uprobe.s:/usr/bin/app:main").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Uprobe);
    assert_eq!(target, "/usr/bin/app:main");

    let spec = parse_program_spec("uprobe.s:/usr/bin/app:main").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::Uprobe);
    assert_eq!(spec.target_string(), "/usr/bin/app:main");
    assert_eq!(spec.section_name(), "uprobe.s//usr/bin/app:main");
    assert_eq!(spec.to_string(), "uprobe.s:/usr/bin/app:main");

    let (prog_type, target) = parse_probe_spec("uretprobe.s:/lib/libc.so.6:malloc").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Uretprobe);
    assert_eq!(target, "/lib/libc.so.6:malloc");

    let spec = parse_program_spec("uretprobe.s:/lib/libc.so.6:malloc").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::Uretprobe);
    assert_eq!(spec.target_string(), "/lib/libc.so.6:malloc");
    assert_eq!(spec.section_name(), "uretprobe.s//lib/libc.so.6:malloc");
    assert_eq!(spec.to_string(), "uretprobe.s:/lib/libc.so.6:malloc");
}

#[test]
fn test_parse_program_spec_uprobe_multi_sections() {
    let (prog_type, target) = parse_probe_spec("uprobe.multi:/bin/bash:read*").unwrap();
    assert_eq!(prog_type, EbpfProgramType::UprobeMulti);
    assert_eq!(target, "/bin/bash:read*");

    let spec = parse_program_spec("uprobe.multi:/bin/bash:read*").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::UprobeMulti {
            target: UprobeMultiTarget {
                binary_path: "/bin/bash".to_string(),
                function_pattern: "read*".to_string(),
            },
            sleepable: false,
        }
    );
    assert_eq!(spec.section_name(), "uprobe.multi//bin/bash:read*");

    let spec = parse_program_spec("uprobe.multi.s:/bin/bash:read*").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::UprobeMulti);
    assert_eq!(spec.section_name(), "uprobe.multi.s//bin/bash:read*");
    assert_eq!(spec.to_string(), "uprobe.multi.s:/bin/bash:read*");

    let (prog_type, target) = parse_probe_spec("uretprobe.multi:/bin/bash:read*").unwrap();
    assert_eq!(prog_type, EbpfProgramType::UretprobeMulti);
    assert_eq!(target, "/bin/bash:read*");

    let spec = parse_program_spec("uretprobe.multi.s:/bin/bash:read*").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::UretprobeMulti);
    assert_eq!(spec.section_name(), "uretprobe.multi.s//bin/bash:read*");
    assert_eq!(spec.to_string(), "uretprobe.multi.s:/bin/bash:read*");
}

#[test]
fn test_parse_program_spec_rejects_invalid_uprobe_multi_target() {
    let err = parse_program_spec("uprobe.multi:/bin/bash")
        .expect_err("expected missing uprobe.multi function pattern to fail");
    assert!(
        matches!(err, LoadError::Load(ref msg) if msg.contains("Invalid uprobe.multi target")),
        "unexpected uprobe.multi validation error: {err:?}"
    );
}

#[test]
fn test_parse_probe_spec_uretprobe() {
    let (prog_type, target) = parse_probe_spec("uretprobe:/lib/libc.so.6:malloc").unwrap();
    assert!(matches!(prog_type, EbpfProgramType::Uretprobe));
    assert_eq!(target, "/lib/libc.so.6:malloc");
}

#[test]
fn test_parse_probe_spec_kprobe_multi_sections() {
    let (prog_type, target) = parse_probe_spec("kprobe.multi:vfs_*").unwrap();
    assert_eq!(prog_type, EbpfProgramType::KprobeMulti);
    assert_eq!(target, "vfs_*");

    let spec = parse_program_spec("kprobe.multi:vfs_*").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::KprobeMulti {
            pattern: "vfs_*".to_string(),
        }
    );
    assert_eq!(spec.section_name(), "kprobe.multi/vfs_*");

    let (prog_type, target) = parse_probe_spec("kretprobe.multi:vfs_*").unwrap();
    assert_eq!(prog_type, EbpfProgramType::KretprobeMulti);
    assert_eq!(target, "vfs_*");

    let spec = parse_program_spec("kretprobe.multi:vfs_*").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::KretprobeMulti {
            pattern: "vfs_*".to_string(),
        }
    );
    assert_eq!(spec.section_name(), "kretprobe.multi/vfs_*");
}

#[test]
fn test_parse_probe_spec_rejects_invalid_kprobe_multi_pattern() {
    let err = parse_program_spec("kprobe.multi:vfs/read")
        .expect_err("expected slash to be rejected in kprobe.multi pattern");

    assert!(
        matches!(err, LoadError::Load(ref msg) if msg.contains("Invalid kprobe multi pattern")),
        "unexpected kprobe.multi validation error: {err:?}"
    );
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
fn test_parse_probe_spec_fmod_ret() {
    let result = parse_probe_spec("fmod_ret:do_sys_openat2");

    match result {
        Ok((prog_type, target)) => {
            assert!(matches!(prog_type, EbpfProgramType::FmodRet));
            assert_eq!(target, "do_sys_openat2");
        }
        Err(LoadError::NeedsSudo) => {}
        Err(LoadError::FunctionNotFound { .. }) => {}
        Err(LoadError::UnsupportedTrampolineTarget { probe_type, .. }) => {
            assert_eq!(probe_type, "fmod_ret");
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_parse_probe_spec_kernel_syscall_probes() {
    let (prog_type, target) = parse_probe_spec("ksyscall:nanosleep").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Ksyscall);
    assert_eq!(target, "nanosleep");

    let spec = parse_program_spec("ksyscall:nanosleep").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::Ksyscall);
    assert_eq!(spec.target_string(), "nanosleep");
    assert_eq!(spec.section_name(), "ksyscall/nanosleep");

    let (prog_type, target) = parse_probe_spec("kretsyscall:nanosleep").unwrap();
    assert_eq!(prog_type, EbpfProgramType::KretSyscall);
    assert_eq!(target, "nanosleep");

    let spec = parse_program_spec("kretsyscall:nanosleep").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::KretSyscall);
    assert_eq!(spec.target_string(), "nanosleep");
    assert_eq!(spec.section_name(), "kretsyscall/nanosleep");
}

#[test]
fn test_parse_probe_spec_tp_btf() {
    let result = parse_probe_spec("tp_btf:sys_enter");

    match result {
        Ok((prog_type, target)) => {
            assert_eq!(prog_type, EbpfProgramType::TpBtf);
            assert_eq!(target, "sys_enter");
        }
        Err(LoadError::UnsupportedTrampolineTarget {
            probe_type, target, ..
        }) => {
            assert_eq!(probe_type, "tp_btf");
            assert_eq!(target, "sys_enter");
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_parse_program_spec_tp_btf_is_structured() {
    let result = parse_program_spec("tp_btf:sys_enter");

    match result {
        Ok(spec) => {
            assert_eq!(
                spec,
                ProgramSpec::TpBtf {
                    name: "sys_enter".to_string(),
                }
            );
            assert_eq!(spec.to_string(), "tp_btf:sys_enter");
        }
        Err(LoadError::UnsupportedTrampolineTarget {
            probe_type, target, ..
        }) => {
            assert_eq!(probe_type, "tp_btf");
            assert_eq!(target, "sys_enter");
        }
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
fn test_parse_probe_spec_raw_tracepoint_writable_alias() {
    let (prog_type, target) = parse_probe_spec("raw_tp.w:sys_enter").unwrap();
    assert_eq!(prog_type, EbpfProgramType::RawTracepointWritable);
    assert_eq!(target, "sys_enter");

    let spec = ProgramSpec::parse("raw_tracepoint.w:sys_enter").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::RawTracepointWritable);
    assert_eq!(spec.target_string(), "sys_enter");
    assert_eq!(spec.section_name(), "raw_tracepoint.w/sys_enter");
}

#[test]
fn test_parse_program_spec_extension_is_structured() {
    let (prog_type, target) = parse_probe_spec("extension:replace_me").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Extension);
    assert_eq!(target, "replace_me");

    let spec = parse_program_spec("freplace:replace_me").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::Extension);
    assert_eq!(spec.target_string(), "replace_me");
    assert_eq!(spec.section_name(), "freplace/replace_me");
}

#[test]
fn test_parse_program_spec_syscall_is_structured() {
    let (prog_type, target) = parse_probe_spec("syscall:demo").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Syscall);
    assert_eq!(target, "demo");

    let spec = parse_program_spec("syscall:demo").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::Syscall);
    assert_eq!(spec.target_string(), "demo");
    assert_eq!(spec.section_name(), "syscall");
}

#[test]
fn test_parse_program_spec_iter_is_structured() {
    let (prog_type, target) = parse_probe_spec("iter:task").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Iter);
    assert_eq!(target, "task");

    let spec = parse_program_spec("iter:task").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::Iter);
    assert_eq!(spec.target_string(), "task");
    assert_eq!(spec.section_name(), "iter/task");
}

#[test]
fn test_parse_probe_spec_xdp() {
    let (prog_type, target) = parse_probe_spec("xdp:lo").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Xdp);
    assert_eq!(target, "lo");
}

#[test]
fn test_parse_probe_spec_xdp_frags() {
    let (prog_type, target) = parse_probe_spec("xdp:lo:frags").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Xdp);
    assert_eq!(target, "lo:frags");
}

#[test]
fn test_parse_probe_spec_xdp_attach_mode() {
    let (prog_type, target) = parse_probe_spec("xdp:lo:drv:frags").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Xdp);
    assert_eq!(target, "lo:drv:frags");

    let (prog_type, target) = parse_probe_spec("xdp:lo:skb:frags").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Xdp);
    assert_eq!(target, "lo:skb:frags");
}

#[test]
fn test_parse_program_spec_xdp_is_structured() {
    let spec = parse_program_spec("xdp:lo").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Xdp {
            target: XdpTarget {
                interface: "lo".to_string(),
                attach_mode: XdpAttachMode::Skb,
                frags: false,
            },
        }
    );
    assert_eq!(spec.to_string(), "xdp:lo");
}

#[test]
fn test_parse_program_spec_xdp_frags_is_structured() {
    let spec = parse_program_spec("xdp:lo:frags").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Xdp {
            target: XdpTarget {
                interface: "lo".to_string(),
                attach_mode: XdpAttachMode::Skb,
                frags: true,
            },
        }
    );
    assert_eq!(spec.to_string(), "xdp:lo:frags");
    assert_eq!(spec.section_name(), "xdp.frags");
}

#[test]
fn test_parse_program_spec_xdp_attach_modes() {
    let spec = parse_program_spec("xdp:lo:drv").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Xdp {
            target: XdpTarget {
                interface: "lo".to_string(),
                attach_mode: XdpAttachMode::Driver,
                frags: false,
            },
        }
    );
    assert_eq!(spec.to_string(), "xdp:lo:drv");

    let spec = parse_program_spec("xdp:lo:hw:frags").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Xdp {
            target: XdpTarget {
                interface: "lo".to_string(),
                attach_mode: XdpAttachMode::Hardware,
                frags: true,
            },
        }
    );
    assert_eq!(spec.to_string(), "xdp:lo:hw:frags");
    assert_eq!(spec.section_name(), "xdp.frags");

    let spec = parse_program_spec("xdp:lo:skb:frags").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Xdp {
            target: XdpTarget {
                interface: "lo".to_string(),
                attach_mode: XdpAttachMode::Skb,
                frags: true,
            },
        }
    );
    assert_eq!(spec.to_string(), "xdp:lo:frags");
}

#[test]
fn test_parse_probe_spec_perf_event() {
    let (prog_type, target) = parse_probe_spec("perf_event:software:cpu-clock").unwrap();
    assert_eq!(prog_type, EbpfProgramType::PerfEvent);
    assert_eq!(target, "software:cpu-clock");
}

#[test]
fn test_parse_probe_spec_socket_filter_udp4() {
    let (prog_type, target) = parse_probe_spec("socket_filter:udp4:127.0.0.1:31337").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SocketFilter);
    assert_eq!(target, "udp4:127.0.0.1:31337");
}

#[test]
fn test_parse_probe_spec_socket_filter_udp6() {
    let (prog_type, target) = parse_probe_spec("socket_filter:udp6:[::1]:31337").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SocketFilter);
    assert_eq!(target, "udp6:[::1]:31337");
}

#[test]
fn test_parse_probe_spec_socket_filter_tcp4() {
    let (prog_type, target) = parse_probe_spec("socket_filter:tcp4:127.0.0.1:31337").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SocketFilter);
    assert_eq!(target, "tcp4:127.0.0.1:31337");
}

#[test]
fn test_parse_probe_spec_socket_filter_tcp6() {
    let (prog_type, target) = parse_probe_spec("socket_filter:tcp6:[::1]:31337").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SocketFilter);
    assert_eq!(target, "tcp6:[::1]:31337");
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
fn test_parse_program_spec_tcx_is_structured() {
    let (prog_type, target) = parse_probe_spec("tcx:lo:egress").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Tcx);
    assert_eq!(target, "lo:egress");

    let spec = parse_program_spec("tcx:lo:egress").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Tcx {
            target: TcTarget {
                interface: "lo".to_string(),
                attach_type: aya::programs::TcAttachType::Egress,
            }
        }
    );
    assert_eq!(spec.to_string(), "tcx:lo:egress");
    assert_eq!(spec.section_name(), "tcx/egress");
}

#[test]
fn test_parse_program_spec_netkit_is_structured() {
    let (prog_type, target) = parse_probe_spec("netkit:lo:peer").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Netkit);
    assert_eq!(target, "lo:peer");

    let spec = parse_program_spec("netkit:lo:peer").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Netkit {
            target: NetkitTarget {
                interface: "lo".to_string(),
                attach_type: NetkitAttachType::Peer,
            }
        }
    );
    assert_eq!(spec.to_string(), "netkit:lo:peer");
    assert_eq!(spec.section_name(), "netkit/peer");
}

#[test]
fn test_parse_program_spec_tc_action_is_structured() {
    let (prog_type, target) = parse_probe_spec("action:demo-action").unwrap();
    assert_eq!(prog_type, EbpfProgramType::TcAction);
    assert_eq!(target, "demo-action");

    let spec = parse_program_spec("tc_action:demo-action").unwrap();
    assert_eq!(spec.program_type(), EbpfProgramType::TcAction);
    assert_eq!(spec.target_string(), "demo-action");
    assert_eq!(spec.to_string(), "tc_action:demo-action");
    assert_eq!(spec.section_name(), "action");
}

#[test]
fn test_program_spec_parse_tracepoint_section_name() {
    let spec = ProgramSpec::parse("tracepoint:sched/sched_switch").unwrap();
    assert_eq!(spec.section_name(), "tracepoint/sched/sched_switch");
}

#[test]
fn test_parse_probe_spec_cgroup_skb_egress() {
    let (prog_type, target) = parse_probe_spec("cgroup_skb:/sys/fs/cgroup:egress").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSkb);
    assert_eq!(target, "/sys/fs/cgroup:egress");
}

#[test]
fn test_parse_probe_spec_cgroup_sock_create() {
    let (prog_type, target) = parse_probe_spec("cgroup_sock:/sys/fs/cgroup:sock_create").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSock);
    assert_eq!(target, "/sys/fs/cgroup:sock_create");
}

#[test]
fn test_parse_probe_spec_cgroup_sysctl_root() {
    let (prog_type, target) = parse_probe_spec("cgroup_sysctl:/sys/fs/cgroup").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSysctl);
    assert_eq!(target, "/sys/fs/cgroup");
}

#[test]
fn test_parse_probe_spec_cgroup_sockopt_get() {
    let (prog_type, target) = parse_probe_spec("cgroup_sockopt:/sys/fs/cgroup:get").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSockopt);
    assert_eq!(target, "/sys/fs/cgroup:get");
}

#[test]
fn test_parse_probe_spec_cgroup_sock_addr_connect4() {
    let (prog_type, target) = parse_probe_spec("cgroup_sock_addr:/sys/fs/cgroup:connect4").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupSockAddr);
    assert_eq!(target, "/sys/fs/cgroup:connect4");
}

#[test]
fn test_parse_probe_spec_sk_lookup_root_netns() {
    let (prog_type, target) = parse_probe_spec("sk_lookup:/proc/self/ns/net").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SkLookup);
    assert_eq!(target, "/proc/self/ns/net");
}

#[test]
fn test_parse_probe_spec_flow_dissector_root_netns() {
    let (prog_type, target) = parse_probe_spec("flow_dissector:/proc/self/ns/net").unwrap();
    assert_eq!(prog_type, EbpfProgramType::FlowDissector);
    assert_eq!(target, "/proc/self/ns/net");
}

#[test]
fn test_parse_probe_spec_sk_reuseport_select() {
    let (prog_type, target) = parse_probe_spec("sk_reuseport:select").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SkReuseport);
    assert_eq!(target, "select");
}

#[test]
fn test_parse_probe_spec_sk_msg_pinned_sockmap() {
    let path = std::env::current_exe().unwrap();
    let spec = format!("sk_msg:{}", path.display());
    let (prog_type, target) = parse_probe_spec(&spec).unwrap();
    assert_eq!(prog_type, EbpfProgramType::SkMsg);
    assert_eq!(target, path.display().to_string());
}

#[test]
fn test_parse_probe_spec_sk_skb_pinned_sockmap() {
    let path = std::env::current_exe().unwrap();
    let spec = format!("sk_skb:{}", path.display());
    let (prog_type, target) = parse_probe_spec(&spec).unwrap();
    assert_eq!(prog_type, EbpfProgramType::SkSkb);
    assert_eq!(target, path.display().to_string());
}

#[test]
fn test_parse_probe_spec_sk_skb_parser_pinned_sockmap() {
    let path = std::env::current_exe().unwrap();
    let spec = format!("sk_skb_parser:{}", path.display());
    let (prog_type, target) = parse_probe_spec(&spec).unwrap();
    assert_eq!(prog_type, EbpfProgramType::SkSkbParser);
    assert_eq!(target, path.display().to_string());
}

#[test]
fn test_parse_program_spec_socket_filter_is_structured() {
    let spec = parse_program_spec("socket_filter:udp4:127.0.0.1:31337").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SocketFilter {
            target: crate::program_spec::SocketFilterTarget {
                socket_kind: crate::program_spec::SocketFilterSocketKind::Udp4,
                bind_ip: "127.0.0.1".to_string(),
                bind_port: 31337,
            }
        }
    );
    assert_eq!(spec.to_string(), "socket_filter:udp4:127.0.0.1:31337");
}

#[test]
fn test_parse_program_spec_socket_filter_udp6_is_structured() {
    let spec = parse_program_spec("socket_filter:udp6:[::1]:31337").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SocketFilter {
            target: crate::program_spec::SocketFilterTarget {
                socket_kind: crate::program_spec::SocketFilterSocketKind::Udp6,
                bind_ip: "::1".to_string(),
                bind_port: 31337,
            }
        }
    );
    assert_eq!(spec.to_string(), "socket_filter:udp6:[::1]:31337");
}

#[test]
fn test_parse_program_spec_socket_filter_tcp4_is_structured() {
    let spec = parse_program_spec("socket_filter:tcp4:127.0.0.1:31337").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SocketFilter {
            target: crate::program_spec::SocketFilterTarget {
                socket_kind: crate::program_spec::SocketFilterSocketKind::Tcp4,
                bind_ip: "127.0.0.1".to_string(),
                bind_port: 31337,
            }
        }
    );
    assert_eq!(spec.to_string(), "socket_filter:tcp4:127.0.0.1:31337");
}

#[test]
fn test_parse_program_spec_socket_filter_tcp6_is_structured() {
    let spec = parse_program_spec("socket_filter:tcp6:[::1]:31337").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SocketFilter {
            target: crate::program_spec::SocketFilterTarget {
                socket_kind: crate::program_spec::SocketFilterSocketKind::Tcp6,
                bind_ip: "::1".to_string(),
                bind_port: 31337,
            }
        }
    );
    assert_eq!(spec.to_string(), "socket_filter:tcp6:[::1]:31337");
}

#[test]
fn test_parse_probe_spec_cgroup_device_root() {
    let (prog_type, target) = parse_probe_spec("cgroup_device:/sys/fs/cgroup").unwrap();
    assert_eq!(prog_type, EbpfProgramType::CgroupDevice);
    assert_eq!(target, "/sys/fs/cgroup");
}

#[test]
fn test_parse_probe_spec_sock_ops_root_cgroup() {
    let (prog_type, target) = parse_probe_spec("sock_ops:/sys/fs/cgroup").unwrap();
    assert_eq!(prog_type, EbpfProgramType::SockOps);
    assert_eq!(target, "/sys/fs/cgroup");
}

#[test]
fn test_parse_probe_spec_lsm_file_open() {
    let (prog_type, target) = parse_probe_spec("lsm:file_open").unwrap();
    assert_eq!(prog_type, EbpfProgramType::Lsm);
    assert_eq!(target, "file_open");
}

#[test]
fn test_parse_probe_spec_lsm_cgroup_socket_bind() {
    let (prog_type, target) = parse_probe_spec("lsm_cgroup:socket_bind").unwrap();
    assert_eq!(prog_type, EbpfProgramType::LsmCgroup);
    assert_eq!(target, "socket_bind");
}

#[test]
fn test_parse_probe_spec_lirc_mode2_dev_null() {
    let (prog_type, target) = parse_probe_spec("lirc_mode2:/dev/null").unwrap();
    assert_eq!(prog_type, EbpfProgramType::LircMode2);
    assert_eq!(target, "/dev/null");
}

#[test]
fn test_parse_program_spec_lsm_is_structured() {
    let spec = parse_program_spec("lsm:file_open").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Lsm {
            hook: "file_open".to_string(),
            sleepable: false,
        }
    );
    assert_eq!(spec.to_string(), "lsm:file_open");
}

#[test]
fn test_parse_program_spec_lsm_cgroup_is_structured() {
    let spec = parse_program_spec("lsm_cgroup:socket_bind").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::LsmCgroup {
            hook: "socket_bind".to_string(),
        }
    );
    assert_eq!(spec.section_name(), "lsm_cgroup/socket_bind");
    assert_eq!(spec.to_string(), "lsm_cgroup:socket_bind");
}

#[test]
fn test_parse_program_spec_sleepable_btf_sections_are_structured() {
    let fentry = ProgramSpec::parse("fentry.s:do_sys_openat2").unwrap();
    assert_eq!(fentry.section_name(), "fentry.s/do_sys_openat2");
    assert_eq!(fentry.to_string(), "fentry.s:do_sys_openat2");

    let fexit = ProgramSpec::parse("fexit.s:do_sys_openat2").unwrap();
    assert_eq!(fexit.section_name(), "fexit.s/do_sys_openat2");
    assert_eq!(fexit.to_string(), "fexit.s:do_sys_openat2");

    let fmod_ret = ProgramSpec::parse("fmod_ret.s:bpf_modify_return_test").unwrap();
    assert_eq!(fmod_ret.section_name(), "fmod_ret.s/bpf_modify_return_test");
    assert_eq!(fmod_ret.to_string(), "fmod_ret.s:bpf_modify_return_test");

    let lsm = ProgramSpec::parse("lsm.s:file_open").unwrap();
    assert_eq!(
        lsm,
        ProgramSpec::Lsm {
            hook: "file_open".to_string(),
            sleepable: true,
        }
    );
    assert_eq!(lsm.section_name(), "lsm.s/file_open");
    assert_eq!(lsm.to_string(), "lsm.s:file_open");
}

#[test]
fn test_parse_program_spec_cgroup_sysctl_is_structured() {
    let spec = parse_program_spec("cgroup_sysctl:/sys/fs/cgroup").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupSysctl {
            target: CgroupSysctlTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
            },
        }
    );
    assert_eq!(spec.to_string(), "cgroup_sysctl:/sys/fs/cgroup");
}

#[test]
fn test_parse_program_spec_cgroup_sock_is_structured() {
    let spec = parse_program_spec("cgroup_sock:/sys/fs/cgroup:sock_create").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupSock {
            target: CgroupSockTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
                attach_type: aya::programs::CgroupSockAttachType::SockCreate,
            }
        }
    );
    assert_eq!(spec.to_string(), "cgroup_sock:/sys/fs/cgroup:sock_create");
}

#[test]
fn test_parse_program_spec_cgroup_sockopt_is_structured() {
    let spec = parse_program_spec("cgroup_sockopt:/sys/fs/cgroup:get").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupSockopt {
            target: CgroupSockoptTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
                attach_type: aya::programs::CgroupSockoptAttachType::Get,
            }
        }
    );
    assert_eq!(spec.to_string(), "cgroup_sockopt:/sys/fs/cgroup:get");
}

#[test]
fn test_program_spec_from_program_type_target_cgroup_sockopt_section_name() {
    let spec =
        ProgramSpec::from_program_type_target(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set")
            .unwrap();
    assert_eq!(spec.section_name(), "cgroup/setsockopt");
}

#[test]
fn test_parse_program_spec_cgroup_sock_addr_is_structured() {
    let spec = parse_program_spec("cgroup_sock_addr:/sys/fs/cgroup:connect4").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupSockAddr {
            target: CgroupSockAddrTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
                attach_type: CgroupSockAddrAttachKind::Connect4,
            }
        }
    );
    assert_eq!(spec.to_string(), "cgroup_sock_addr:/sys/fs/cgroup:connect4");
}

#[test]
fn test_parse_program_spec_cgroup_sock_addr_unix_is_structured() {
    let spec = parse_program_spec("cgroup_sock_addr:/sys/fs/cgroup:connect_unix").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupSockAddr {
            target: CgroupSockAddrTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
                attach_type: CgroupSockAddrAttachKind::ConnectUnix,
            }
        }
    );
    assert_eq!(
        spec.to_string(),
        "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
    );
    assert_eq!(spec.section_name(), "cgroup/connect_unix");
}

#[test]
fn test_parse_program_spec_sk_lookup_is_structured() {
    let spec = parse_program_spec("sk_lookup:/proc/self/ns/net").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SkLookup {
            target: SkLookupTarget {
                netns_path: "/proc/self/ns/net".to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), "sk_lookup:/proc/self/ns/net");
}

#[test]
fn test_parse_program_spec_flow_dissector_is_structured() {
    let spec = parse_program_spec("flow_dissector:/proc/self/ns/net").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::FlowDissector {
            target: FlowDissectorTarget {
                netns_path: "/proc/self/ns/net".to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), "flow_dissector:/proc/self/ns/net");
    assert_eq!(spec.section_name(), "flow_dissector");
}

#[test]
fn test_parse_program_spec_netfilter_is_structured() {
    let spec = parse_program_spec("netfilter:ipv4:pre_routing:priority=-100:defrag").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::Netfilter {
            target: NetfilterTarget {
                family: NetfilterProtocolFamily::Ipv4,
                hook: NetfilterHook::PreRouting,
                priority: -100,
                defrag: true,
            }
        }
    );
    assert_eq!(
        spec.to_string(),
        "netfilter:ipv4:pre_routing:priority=-100:defrag"
    );
    assert_eq!(spec.section_name(), "netfilter");

    let ipv6 = parse_program_spec("netfilter:ip6:localin").unwrap();
    assert_eq!(ipv6.to_string(), "netfilter:ipv6:local_in");
    assert_eq!(ipv6.section_name(), "netfilter");
}

#[test]
fn test_parse_program_spec_lwt_sections_are_structured() {
    for (spec_string, expected_type, expected_section) in [
        ("lwt_in:demo-route", EbpfProgramType::LwtIn, "lwt_in"),
        ("lwt_out:demo-route", EbpfProgramType::LwtOut, "lwt_out"),
        ("lwt_xmit:demo-route", EbpfProgramType::LwtXmit, "lwt_xmit"),
        (
            "lwt_seg6local:demo-route",
            EbpfProgramType::LwtSeg6Local,
            "lwt_seg6local",
        ),
    ] {
        let spec = parse_program_spec(spec_string).unwrap();
        assert_eq!(spec.program_type(), expected_type);
        assert_eq!(spec.target_string(), "demo-route");
        assert_eq!(spec.to_string(), spec_string);
        assert_eq!(spec.section_name(), expected_section);
    }
}

#[test]
fn test_parse_program_spec_sk_reuseport_sections_are_structured() {
    let select = parse_program_spec("sk_reuseport:select").unwrap();
    assert_eq!(
        select,
        ProgramSpec::SkReuseport {
            target: SkReuseportTarget {
                mode: SkReuseportMode::Select,
            }
        }
    );
    assert_eq!(select.to_string(), "sk_reuseport:select");
    assert_eq!(select.section_name(), "sk_reuseport");

    let migrate = parse_program_spec("sk_reuseport:migrate").unwrap();
    assert_eq!(
        migrate,
        ProgramSpec::SkReuseport {
            target: SkReuseportTarget {
                mode: SkReuseportMode::Migrate,
            }
        }
    );
    assert_eq!(migrate.to_string(), "sk_reuseport:migrate");
    assert_eq!(migrate.section_name(), "sk_reuseport/migrate");
}

#[test]
fn test_parse_program_spec_lirc_mode2_is_structured() {
    let spec = parse_program_spec("lirc_mode2:/dev/null").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::LircMode2 {
            target: crate::program_spec::LircMode2Target {
                device_path: "/dev/null".to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), "lirc_mode2:/dev/null");
}

#[test]
fn test_parse_program_spec_sk_msg_is_structured() {
    let path = std::env::current_exe().unwrap();
    let spec_string = format!("sk_msg:{}", path.display());
    let spec = parse_program_spec(&spec_string).unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SkMsg {
            target: SkMsgTarget {
                map_path: path.display().to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), spec_string);
}

#[test]
fn test_parse_program_spec_sk_skb_is_structured() {
    let path = std::env::current_exe().unwrap();
    let spec_string = format!("sk_skb:{}", path.display());
    let spec = parse_program_spec(&spec_string).unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SkSkb {
            target: crate::program_spec::SkSkbTarget {
                map_path: path.display().to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), spec_string);
}

#[test]
fn test_parse_program_spec_sk_skb_parser_is_structured() {
    let path = std::env::current_exe().unwrap();
    let spec_string = format!("sk_skb_parser:{}", path.display());
    let spec = parse_program_spec(&spec_string).unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SkSkbParser {
            target: crate::program_spec::SkSkbTarget {
                map_path: path.display().to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), spec_string);
}

#[test]
fn test_parse_program_spec_for_attach_allows_missing_socket_maps_on_dry_run() {
    let missing_path = "/__nu_plugin_ebpf_missing_sockmap__";
    for (spec_string, expected_type) in [
        (format!("sk_msg:{missing_path}"), EbpfProgramType::SkMsg),
        (format!("sk_skb:{missing_path}"), EbpfProgramType::SkSkb),
        (
            format!("sk_skb_parser:{missing_path}"),
            EbpfProgramType::SkSkbParser,
        ),
    ] {
        let spec = parse_program_spec_for_attach(&spec_string, true)
            .expect("socket-map dry-run should not require a live pinned map");
        assert_eq!(spec.program_type(), expected_type);
        assert_eq!(spec.pinned_map_path(), Some(missing_path));

        let err = parse_program_spec_for_attach(&spec_string, false)
            .expect_err("live socket-map attach should still require a pinned map");
        assert!(
            err.to_string().contains("Unknown pinned sockmap path"),
            "unexpected live attach error: {err}"
        );
    }
}

#[test]
fn test_parse_program_spec_for_attach_keeps_other_dry_run_validation() {
    let err = parse_program_spec_for_attach("xdp:__nu_plugin_ebpf_no_such_iface__", true)
        .expect_err("dry-run should only skip socket-map path existence checks");
    assert!(
        err.to_string().contains("Unknown network interface"),
        "unexpected dry-run validation error: {err}"
    );
}

#[test]
fn test_parse_program_spec_cgroup_device_is_structured() {
    let spec = parse_program_spec("cgroup_device:/sys/fs/cgroup").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::CgroupDevice {
            target: crate::program_spec::CgroupDeviceTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), "cgroup_device:/sys/fs/cgroup");
}

#[test]
fn test_parse_program_spec_sock_ops_is_structured() {
    let spec = parse_program_spec("sock_ops:/sys/fs/cgroup").unwrap();
    assert_eq!(
        spec,
        ProgramSpec::SockOps {
            target: crate::program_spec::SockOpsTarget {
                cgroup_path: "/sys/fs/cgroup".to_string(),
            }
        }
    );
    assert_eq!(spec.to_string(), "sock_ops:/sys/fs/cgroup");
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
fn test_merge_generic_map_key_types_drops_conflicts() {
    let shared = MapRef {
        name: "shared_keyed".to_string(),
        kind: MapKind::Hash,
    };
    let unique = MapRef {
        name: "other_keyed".to_string(),
        kind: MapKind::Hash,
    };
    let record_key = MirType::Struct {
        name: Some("key".to_string()),
        kernel_btf_type_id: None,
        fields: vec![],
    };
    let other_key = MirType::U64;
    let conflicting_key = MirType::I64;

    let merged = EbpfState::merge_generic_map_types(
        [
            HashMap::from([
                (shared.clone(), record_key.clone()),
                (unique.clone(), other_key.clone()),
            ]),
            HashMap::from([(shared.clone(), record_key)]),
            HashMap::from([(shared.clone(), conflicting_key)]),
        ]
        .iter(),
    );

    assert_eq!(merged.get(&unique), Some(&other_key));
    assert!(!merged.contains_key(&shared));
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
fn test_merge_generic_map_max_entries_drops_conflicts() {
    let shared = MapRef {
        name: "shared_capacity".to_string(),
        kind: MapKind::Hash,
    };
    let unique = MapRef {
        name: "other_capacity".to_string(),
        kind: MapKind::Hash,
    };

    let merged = EbpfState::merge_generic_map_max_entries(
        [
            HashMap::from([(shared.clone(), 128), (unique.clone(), 64)]),
            HashMap::from([(shared.clone(), 128)]),
            HashMap::from([(shared.clone(), 256)]),
        ]
        .iter(),
    );

    assert_eq!(merged.get(&unique), Some(&64));
    assert!(!merged.contains_key(&shared));
}

#[test]
fn test_merge_generic_map_value_semantics_drops_conflicts() {
    let shared = MapRef {
        name: "shared_state".to_string(),
        kind: MapKind::Hash,
    };
    let unique = MapRef {
        name: "other_state".to_string(),
        kind: MapKind::Hash,
    };
    let string_semantics = AnnotatedValueSemantics::Record(vec![(
        "msg".to_string(),
        AnnotatedValueSemantics::String {
            slot_len: 16,
            content_cap: 15,
        },
    )]);
    let list_semantics = AnnotatedValueSemantics::Record(vec![(
        "vals".to_string(),
        AnnotatedValueSemantics::NumericList { max_len: 2 },
    )]);

    let merged = EbpfState::merge_generic_map_value_semantics(
        [
            HashMap::from([
                (shared.clone(), string_semantics.clone()),
                (unique.clone(), list_semantics.clone()),
            ]),
            HashMap::from([(shared.clone(), string_semantics.clone())]),
            HashMap::from([(shared.clone(), list_semantics.clone())]),
        ]
        .iter(),
    );

    assert_eq!(merged.get(&unique), Some(&list_semantics));
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
fn test_attach_rejects_risky_struct_ops_without_explicit_opt_in() {
    let state = EbpfState::new();
    let object = EbpfObject::struct_ops("sched_ext_ops", "sched_ext_ops", vec![0; 8]).build();

    let err = state
        .attach(&object)
        .expect_err("risky struct_ops objects should require explicit opt-in");

    assert!(
        matches!(
            err,
            LoadError::Attach(ref msg)
                if msg.contains("requires explicit opt-in")
                    && msg.contains("sched_ext")
                    && msg.contains("--unsafe-struct-ops")
        ),
        "unexpected risky struct_ops attach error: {err:?}"
    );

    for value_type_name in ["demo_ops", "hid_bpf_ops", "Qdisc_ops"] {
        let object = EbpfObject::struct_ops(value_type_name, value_type_name, vec![0; 8]).build();
        let err = state.attach(&object).expect_err(
            "unclassified or behavior-changing struct_ops objects should require explicit opt-in",
        );
        assert!(
            matches!(
                err,
                LoadError::Attach(ref msg)
                    if msg.contains("requires explicit opt-in")
                        && msg.contains(value_type_name)
                        && msg.contains("--unsafe-struct-ops")
            ),
            "unexpected struct_ops attach error for {value_type_name}: {err:?}"
        );
    }
}

#[test]
fn test_attach_rejects_struct_ops_callback_program_before_loading() {
    let state = EbpfState::new();
    let object = EbpfProgram::from_bytecode(
        EbpfProgramType::StructOps,
        "sched_ext_ops.init",
        "init",
        vec![],
    )
    .into_object();

    let err = state
        .attach(&object)
        .expect_err("struct_ops callbacks should reject before ELF emission");

    assert!(
        matches!(
            err,
            LoadError::Attach(ref msg)
                if msg.contains("live attach for struct_ops programs is not supported by this loader yet")
                    && msg.contains("struct_ops callbacks")
                    && msg.contains("not directly attachable")
                    && msg.contains("use --dry-run to compile")
        ),
        "unexpected struct_ops callback live-attach error: {err:?}"
    );
}

#[test]
fn test_attach_rejects_compile_only_programs_before_loading() {
    let state = EbpfState::new();

    for (prog_type, target, label, detail) in [
        (
            EbpfProgramType::RawTracepointWritable,
            "sys_enter",
            "raw_tracepoint.w",
            "does not preserve writable raw-tracepoint sections",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            "tc_action",
            "does not expose a tc_action attach wrapper",
        ),
        (
            EbpfProgramType::Netkit,
            "lo:primary",
            "netkit",
            "does not expose a netkit attach wrapper",
        ),
        (
            EbpfProgramType::FmodRet,
            "do_sys_openat2",
            "fmod_ret",
            "does not expose BPF_MODIFY_RETURN/fmod_ret loading and attach support",
        ),
        (
            EbpfProgramType::LsmCgroup,
            "socket_bind",
            "lsm_cgroup",
            "requires cgroup-aware BPF link setup",
        ),
        (
            EbpfProgramType::SkReuseport,
            "select",
            "sk_reuseport",
            "does not expose a sk_reuseport attach wrapper",
        ),
        (
            EbpfProgramType::FlowDissector,
            "/proc/self/ns/net",
            "flow_dissector",
            "does not expose a flow-dissector attach wrapper",
        ),
        (
            EbpfProgramType::Netfilter,
            "ipv4:pre_routing",
            "netfilter",
            "needs BPF-link netfilter attach support",
        ),
        (
            EbpfProgramType::LwtIn,
            "demo-route",
            "lwt_in",
            "needs route LWT attach support",
        ),
        (
            EbpfProgramType::LwtOut,
            "demo-route",
            "lwt_out",
            "needs route LWT attach support",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            "lwt_xmit",
            "needs route LWT attach support",
        ),
        (
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
            "lwt_seg6local",
            "needs route LWT attach support",
        ),
        (
            EbpfProgramType::Extension,
            "replace_me",
            "freplace",
            "requires a loaded target program and BTF/function pairing",
        ),
        (
            EbpfProgramType::Syscall,
            "demo",
            "syscall",
            "has no ordinary hook attach in this loader",
        ),
        (
            EbpfProgramType::Iter,
            "task",
            "iter",
            "needs BPF iterator link/seq-file attach support",
        ),
    ] {
        let object = EbpfProgram::from_bytecode(prog_type, target, "main", vec![]).into_object();
        let err = state
            .attach(&object)
            .expect_err("compile-only programs should reject live attach before ELF emission");

        assert!(
            matches!(
                err,
                LoadError::Attach(ref msg)
                    if msg.contains(&format!(
                        "live attach for {label} programs is not supported by this loader yet"
                    )) && msg.contains(detail) && msg.contains("use --dry-run to compile")
            ),
            "unexpected live-attach error for {label}: {err:?}"
        );
        if let LoadError::Attach(msg) = &err {
            for requirement in prog_type.compatibility_requirements() {
                assert!(
                    msg.contains(requirement.description()),
                    "{label} live-attach error should mention compatibility requirement {requirement:?}: {msg}"
                );
                if let Some(minimum_kernel) = requirement.minimum_kernel() {
                    assert!(
                        msg.contains(&format!("kernel>={minimum_kernel}")),
                        "{label} live-attach error should mention minimum kernel for {requirement:?}: {msg}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_attach_rejects_compile_only_programs_with_spec_requirements() {
    let state = EbpfState::new();
    let spec = ProgramSpec::parse("fmod_ret.s:bpf_modify_return_test")
        .expect("sleepable fmod_ret spec should parse");
    let object = EbpfProgram::from_bytecode(
        EbpfProgramType::FmodRet,
        "bpf_modify_return_test",
        "main",
        vec![],
    )
    .with_program_spec(spec)
    .into_object();

    let err = state
        .attach(&object)
        .expect_err("compile-only sleepable fmod_ret should reject before ELF emission");

    let LoadError::Attach(msg) = err else {
        panic!("expected attach error for sleepable fmod_ret");
    };
    assert!(msg.contains("live attach for fmod_ret programs is not supported by this loader yet"));
    assert!(msg.contains(ProgramCompatibilityRequirement::KernelBtf.description()));
    assert!(msg.contains(ProgramCompatibilityRequirement::BpfTrampoline.description()));
    assert!(msg.contains(ProgramCompatibilityRequirement::SleepableProgram.description()));
    assert!(msg.contains("kernel>=5.2"));
    assert!(msg.contains("kernel>=5.5"));
    assert!(msg.contains("kernel>=5.10"));
}

#[test]
fn test_attach_rejects_cgroup_sock_addr_unix_before_loading() {
    let state = EbpfState::new();
    let object = EbpfProgram::from_bytecode(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
        "main",
        vec![],
    )
    .into_object();

    let err = state
        .attach(&object)
        .expect_err("cgroup_sock_addr unix hooks should reject live attach before ELF emission");

    let expected_requirements = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
        .expect("cgroup_sock_addr unix spec should parse")
        .compatibility_requirements();

    assert!(
        matches!(
            err,
            LoadError::Attach(ref msg)
                if msg.contains("live attach for cgroup_sock_addr connect_unix hooks is not supported by this loader yet")
                    && msg.contains("does not expose BPF_CGROUP_UNIX_* hooks")
                    && msg.contains("use --dry-run to compile")
        ),
        "unexpected cgroup_sock_addr unix live-attach error: {err:?}"
    );
    if let LoadError::Attach(msg) = &err {
        for requirement in expected_requirements {
            assert!(
                msg.contains(requirement.description()),
                "cgroup_sock_addr unix live-attach error should mention compatibility requirement {requirement:?}: {msg}"
            );
            if let Some(minimum_kernel) = requirement.minimum_kernel() {
                assert!(
                    msg.contains(&format!("kernel>={minimum_kernel}")),
                    "cgroup_sock_addr unix live-attach error should mention minimum kernel for {requirement:?}: {msg}"
                );
            }
        }
    }
}

#[test]
fn test_kernel_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [
        ProgramCompatibilityRequirement::KernelBtf,
        ProgramCompatibilityRequirement::BpfTrampoline,
        ProgramCompatibilityRequirement::SleepableProgram,
    ];
    let msg = kernel_minimum_requirement_detail(&requirements, "5.4.0-test")
        .expect("kernel 5.4 should be too old for sleepable trampoline programs");

    assert!(msg.contains("parsed target requires kernel>=5.10"));
    assert!(msg.contains("current kernel is 5.4.0-test"));
    assert!(msg.contains(ProgramCompatibilityRequirement::SleepableProgram.description()));
    assert!(msg.contains("kernel>=5.10"));
}

#[test]
fn test_kernel_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [
        ProgramCompatibilityRequirement::KernelBtf,
        ProgramCompatibilityRequirement::BpfTrampoline,
        ProgramCompatibilityRequirement::SleepableProgram,
    ];
    assert!(kernel_minimum_requirement_detail(&requirements, "5.10.0").is_none());
    assert!(kernel_minimum_requirement_detail(&requirements, "6.1.12").is_none());
}

#[test]
fn test_kernel_minimum_requirement_detail_reports_sched_ext_struct_ops_floor() {
    let requirements = ProgramSpec::parse("struct_ops:sched_ext_ops")
        .expect("sched_ext struct_ops spec should parse")
        .compatibility_requirements();
    let msg = kernel_minimum_requirement_detail(&requirements, "6.11.0-test")
        .expect("kernel 6.11 should be too old for sched_ext struct_ops");

    assert!(msg.contains("parsed target requires kernel>=6.12"));
    assert!(msg.contains("current kernel is 6.11.0-test"));
    assert!(msg.contains(ProgramCompatibilityRequirement::StructOps.description()));
    assert!(msg.contains(ProgramCompatibilityRequirement::SchedExt.description()));
    assert!(msg.contains("kernel>=5.6"));
    assert!(msg.contains("kernel>=6.12"));
}

#[test]
fn test_kernel_map_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [
        MapKind::Hash.compatibility_requirement(),
        MapKind::RingBuf.compatibility_requirement(),
    ];
    let msg = kernel_map_minimum_requirement_detail(&requirements, "5.4.0-test")
        .expect("kernel 5.4 should be too old for ringbuf maps");

    assert!(msg.contains("compiled maps require kernel>=5.8"));
    assert!(msg.contains("current kernel is 5.4.0-test"));
    assert!(msg.contains("BPF_MAP_TYPE_RINGBUF map support"));
    assert!(msg.contains("kernel>=5.8"));
}

#[test]
fn test_kernel_map_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [
        MapKind::Hash.compatibility_requirement(),
        MapKind::RingBuf.compatibility_requirement(),
    ];
    assert!(kernel_map_minimum_requirement_detail(&requirements, "5.8.0").is_none());
    assert!(kernel_map_minimum_requirement_detail(&requirements, "6.1.12").is_none());
    assert!(kernel_map_minimum_requirement_detail(&[], "3.19").is_none());
}

#[test]
fn test_kernel_map_value_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [
        MapValueCompatibilityRequirement::BpfSpinLock,
        MapValueCompatibilityRequirement::BpfTimer,
        MapValueCompatibilityRequirement::BpfRefcount,
        MapValueCompatibilityRequirement::BpfKptr,
    ];
    let msg = kernel_map_value_minimum_requirement_detail(&requirements, "6.3.12-test")
        .expect("kernel 6.3 should be too old for refcount map-value fields");

    assert!(msg.contains("compiled map-value fields require kernel>=6.4"));
    assert!(msg.contains("current kernel is 6.3.12-test"));
    assert!(msg.contains("BPF map-value spin lock field support"));
    assert!(msg.contains("BPF map-value timer field support"));
    assert!(msg.contains("BPF map-value refcount field support"));
    assert!(msg.contains("BPF map-value kptr field support"));
    assert!(msg.contains("kernel>=6.4"));
}

#[test]
fn test_kernel_map_value_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [
        MapValueCompatibilityRequirement::BpfSpinLock,
        MapValueCompatibilityRequirement::BpfTimer,
        MapValueCompatibilityRequirement::BpfKptr,
        MapValueCompatibilityRequirement::BpfRefcount,
        MapValueCompatibilityRequirement::BpfWorkqueue,
    ];
    assert!(kernel_map_value_minimum_requirement_detail(&requirements, "6.10.0").is_none());
    assert!(kernel_map_value_minimum_requirement_detail(&requirements, "6.12.1").is_none());
    assert!(kernel_map_value_minimum_requirement_detail(&[], "3.19").is_none());
}

#[test]
fn test_kernel_global_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [GlobalCompatibilityRequirement::BpfDataSections];
    let msg = kernel_global_minimum_requirement_detail(&requirements, "5.1.21-test")
        .expect("kernel 5.1 should be too old for global data sections");

    assert!(msg.contains("compiled global data sections require kernel>=5.2"));
    assert!(msg.contains("current kernel is 5.1.21-test"));
    assert!(msg.contains("BPF global data-section support"));
    assert!(msg.contains("kernel>=5.2"));
}

#[test]
fn test_kernel_global_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [GlobalCompatibilityRequirement::BpfDataSections];
    assert!(kernel_global_minimum_requirement_detail(&requirements, "5.2.0").is_none());
    assert!(kernel_global_minimum_requirement_detail(&requirements, "6.1.12").is_none());
    assert!(kernel_global_minimum_requirement_detail(&[], "3.19").is_none());
}

#[test]
fn test_kernel_helper_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [
        BpfHelper::MapLookupElem
            .compatibility_requirement()
            .expect("map lookup helper should be versioned"),
        BpfHelper::RingbufReserve
            .compatibility_requirement()
            .expect("ringbuf reserve helper should be versioned"),
    ];
    let msg = kernel_helper_minimum_requirement_detail(&requirements, "5.4.0-test")
        .expect("kernel 5.4 should be too old for ringbuf helpers");

    assert!(msg.contains("compiled helpers require kernel>=5.8"));
    assert!(msg.contains("current kernel is 5.4.0-test"));
    assert!(msg.contains("bpf_ringbuf_reserve helper support"));
    assert!(msg.contains("kernel>=5.8"));
}

#[test]
fn test_kernel_helper_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [
        BpfHelper::MapLookupElem
            .compatibility_requirement()
            .expect("map lookup helper should be versioned"),
        BpfHelper::RingbufReserve
            .compatibility_requirement()
            .expect("ringbuf reserve helper should be versioned"),
    ];
    assert!(kernel_helper_minimum_requirement_detail(&requirements, "5.8.0").is_none());
    assert!(kernel_helper_minimum_requirement_detail(&requirements, "6.1.12").is_none());
    assert!(kernel_helper_minimum_requirement_detail(&[], "3.19").is_none());
}

#[test]
fn test_kernel_context_field_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [
        ContextFieldCompatibilityRequirement::for_field(&CtxField::Pid)
            .expect("pid context field should be versioned"),
        ContextFieldCompatibilityRequirement::for_field(&CtxField::EgressIfindex)
            .expect("egress_ifindex context field should be versioned"),
    ];
    let msg = kernel_context_field_minimum_requirement_detail(&requirements, "5.4.0-test")
        .expect("kernel 5.4 should be too old for egress_ifindex");

    assert!(msg.contains("compiled context fields require kernel>=5.8"));
    assert!(msg.contains("current kernel is 5.4.0-test"));
    assert!(msg.contains("ctx.egress_ifindex context field support"));
    assert!(msg.contains("kernel>=5.8"));
}

#[test]
fn test_kernel_context_field_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [
        ContextFieldCompatibilityRequirement::for_field(&CtxField::Pid)
            .expect("pid context field should be versioned"),
        ContextFieldCompatibilityRequirement::for_field(&CtxField::EgressIfindex)
            .expect("egress_ifindex context field should be versioned"),
    ];
    assert!(kernel_context_field_minimum_requirement_detail(&requirements, "5.8.0").is_none());
    assert!(kernel_context_field_minimum_requirement_detail(&requirements, "6.1.12").is_none());
    assert!(kernel_context_field_minimum_requirement_detail(&[], "3.19").is_none());
}

#[test]
fn test_kernel_kfunc_minimum_requirement_detail_reports_too_old_kernel() {
    let requirements = [
        KfuncCompatibilityRequirement::for_name("bpf_task_acquire")
            .expect("task acquire kfunc should be versioned"),
        KfuncCompatibilityRequirement::for_name("bpf_get_task_exe_file")
            .expect("file kfunc should be versioned"),
    ];
    let msg = kernel_kfunc_minimum_requirement_detail(&requirements, "6.8.0-test")
        .expect("kernel 6.8 should be too old for bpf_get_task_exe_file");

    assert!(msg.contains("compiled kfuncs require kernel>=6.12"));
    assert!(msg.contains("current kernel is 6.8.0-test"));
    assert!(msg.contains("bpf_get_task_exe_file kfunc support"));
    assert!(msg.contains("kernel>=6.12"));
}

#[test]
fn test_kernel_kfunc_minimum_requirement_detail_accepts_newer_kernel() {
    let requirements = [
        KfuncCompatibilityRequirement::for_name("bpf_task_acquire")
            .expect("task acquire kfunc should be versioned"),
        KfuncCompatibilityRequirement::for_name("bpf_get_task_exe_file")
            .expect("file kfunc should be versioned"),
    ];
    assert!(kernel_kfunc_minimum_requirement_detail(&requirements, "6.12.0").is_none());
    assert!(kernel_kfunc_minimum_requirement_detail(&requirements, "6.13.1").is_none());
    assert!(kernel_kfunc_minimum_requirement_detail(&[], "6.1").is_none());
}

#[test]
fn test_kernel_kfunc_requirement_detail_reports_too_new_kernel_window() {
    let requirements = [
        KfuncCompatibilityRequirement::for_name("scx_bpf_reenqueue_local")
            .expect("legacy sched_ext reenqueue kfunc should be versioned"),
    ];
    let msg = kernel_kfunc_minimum_requirement_detail(&requirements, "6.23.0")
        .expect("kernel 6.23 should be too new for legacy reenqueue_local");

    assert!(msg.contains("compiled kfuncs include kfuncs unavailable on kernel>=6.23"));
    assert!(msg.contains("current kernel is 6.23.0"));
    assert!(msg.contains("scx_bpf_reenqueue_local kfunc support"));
    assert!(msg.contains("kernel>=6.12, kernel<6.23"));
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
