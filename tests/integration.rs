//! Integration tests for nu_plugin_ebpf commands
//!
//! These tests verify the plugin's functionality at the command level.
//! Tests that require elevated privileges are skipped when not running as root.

#[cfg(target_os = "linux")]
mod linux_tests {
    use nu_plugin_ebpf::loader::{
        LoadError, PerfEventEvent, PerfEventHardwareEvent, PerfEventSamplePolicy,
        PerfEventSoftwareEvent, PerfEventTarget, ProgramSpec, UprobeTarget, parse_probe_spec,
        parse_program_spec,
    };

    /// Test parsing valid kprobe specification
    #[test]
    fn test_parse_kprobe_spec() {
        // Note: This may fail with NeedsSudo if not running as root
        // That's expected - we're testing the parsing behavior
        let result = parse_probe_spec("kprobe:some_function");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("Kprobe"),
                    "Expected Kprobe type"
                );
                assert_eq!(target, "some_function");
            }
            Err(LoadError::NeedsSudo) => {
                // Expected when running without privileges
            }
            Err(LoadError::FunctionNotFound { .. }) => {
                // Expected if the function doesn't exist in kernel
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing valid tracepoint specification
    #[test]
    fn test_parse_tracepoint_spec() {
        let result = parse_probe_spec("tracepoint:syscalls/sys_enter_openat");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("Tracepoint"),
                    "Expected Tracepoint type"
                );
                assert_eq!(target, "syscalls/sys_enter_openat");
            }
            Err(LoadError::TracepointNotFound { .. }) => {
                // Expected if tracefs is not available or tracepoint doesn't exist
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing valid fentry specification
    #[test]
    fn test_parse_fentry_spec() {
        let result = parse_probe_spec("fentry:do_sys_openat2");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("Fentry"),
                    "Expected Fentry type"
                );
                assert_eq!(target, "do_sys_openat2");
            }
            Err(LoadError::NeedsSudo) => {}
            Err(LoadError::FunctionNotFound { .. }) => {}
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing valid fexit specification
    #[test]
    fn test_parse_fexit_spec() {
        let result = parse_probe_spec("fexit:do_sys_openat2");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("Fexit"),
                    "Expected Fexit type"
                );
                assert_eq!(target, "do_sys_openat2");
            }
            Err(LoadError::NeedsSudo) => {}
            Err(LoadError::FunctionNotFound { .. }) => {}
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_parse_cgroup_sock_addr_spec() {
        let result = parse_probe_spec("cgroup_sock_addr:/sys/fs/cgroup:connect4");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("CgroupSockAddr"),
                    "Expected CgroupSockAddr type"
                );
                assert_eq!(target, "/sys/fs/cgroup:connect4");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_parse_structured_tracepoint_spec() {
        let result = parse_program_spec("tracepoint:syscalls/sys_enter_openat");

        match result {
            Ok(ProgramSpec::Tracepoint { category, name }) => {
                assert_eq!(category, "syscalls");
                assert_eq!(name, "sys_enter_openat");
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_parse_structured_xdp_spec() {
        let result = parse_program_spec("xdp:lo");

        match result {
            Ok(ProgramSpec::Xdp { interface }) => assert_eq!(interface, "lo"),
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_parse_structured_perf_event_spec() {
        let result = parse_program_spec("perf_event:software:cpu-clock:period=100000");

        match result {
            Ok(ProgramSpec::PerfEvent { target }) => {
                assert_eq!(
                    target,
                    PerfEventTarget {
                        event: PerfEventEvent::Software(PerfEventSoftwareEvent::CpuClock),
                        cpu: None,
                        pid: None,
                        sample_policy: PerfEventSamplePolicy::Period(100000),
                    }
                );
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_parse_structured_perf_event_context_switches_spec() {
        let result = parse_program_spec("perf_event:software:context-switches");

        match result {
            Ok(ProgramSpec::PerfEvent { target }) => {
                assert_eq!(
                    target,
                    PerfEventTarget {
                        event: PerfEventEvent::Software(PerfEventSoftwareEvent::ContextSwitches),
                        cpu: None,
                        pid: None,
                        sample_policy: PerfEventSamplePolicy::Period(1_000_000),
                    }
                );
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_parse_structured_perf_event_hardware_spec() {
        let result = parse_program_spec("perf_event:hardware:cache-misses:freq=99");

        match result {
            Ok(ProgramSpec::PerfEvent { target }) => {
                assert_eq!(
                    target,
                    PerfEventTarget {
                        event: PerfEventEvent::Hardware(PerfEventHardwareEvent::CacheMisses),
                        cpu: None,
                        pid: None,
                        sample_policy: PerfEventSamplePolicy::Frequency(99),
                    }
                );
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_parse_structured_perf_event_pid_selector_spec() {
        let result = parse_program_spec("perf_event:hardware:instructions:pid=321");

        match result {
            Ok(ProgramSpec::PerfEvent { target }) => {
                assert_eq!(
                    target,
                    PerfEventTarget {
                        event: PerfEventEvent::Hardware(PerfEventHardwareEvent::Instructions),
                        cpu: None,
                        pid: Some(321),
                        sample_policy: PerfEventSamplePolicy::Period(1_000_000),
                    }
                );
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_parse_structured_struct_ops_spec() {
        let result = parse_program_spec("struct_ops:file");

        match result {
            Ok(ProgramSpec::StructOps { value_type_name }) => {
                assert_eq!(value_type_name, "file");
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    /// Test parsing uprobe specification
    #[test]
    fn test_parse_uprobe_spec() {
        let result = parse_probe_spec("uprobe:/usr/bin/ls:main");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("Uprobe"),
                    "Expected Uprobe type"
                );
                assert_eq!(target, "/usr/bin/ls:main");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing uretprobe specification
    #[test]
    fn test_parse_uretprobe_spec() {
        let result = parse_probe_spec("uretprobe:/lib/libc.so.6:malloc");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("Uretprobe"),
                    "Expected Uretprobe type"
                );
                assert_eq!(target, "/lib/libc.so.6:malloc");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing raw tracepoint specification
    #[test]
    fn test_parse_raw_tracepoint_spec() {
        let result = parse_probe_spec("raw_tracepoint:sys_enter");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("RawTracepoint"),
                    "Expected RawTracepoint type"
                );
                assert_eq!(target, "sys_enter");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing cgroup_skb specification
    #[test]
    fn test_parse_cgroup_skb_spec() {
        let result = parse_probe_spec("cgroup_skb:/sys/fs/cgroup:egress");

        match result {
            Ok((prog_type, target)) => {
                assert!(
                    format!("{:?}", prog_type).contains("CgroupSkb"),
                    "Expected CgroupSkb type"
                );
                assert_eq!(target, "/sys/fs/cgroup:egress");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    /// Test parsing invalid probe specification (no colon)
    #[test]
    fn test_parse_invalid_spec_no_colon() {
        let result = parse_probe_spec("kprobe_sys_clone");
        assert!(result.is_err(), "Expected error for spec without colon");
    }

    /// Test parsing invalid probe specification (unknown type)
    #[test]
    fn test_parse_invalid_spec_unknown_type() {
        let result = parse_probe_spec("invalid:target");
        assert!(result.is_err(), "Expected error for unknown probe type");
    }

    /// Test UprobeTarget parsing - basic function
    #[test]
    fn test_uprobe_target_basic_function() {
        let target = UprobeTarget::parse("/usr/bin/python:Py_Initialize").unwrap();
        assert_eq!(target.binary_path, "/usr/bin/python");
        assert_eq!(target.function_name, Some("Py_Initialize".to_string()));
        assert_eq!(target.offset, 0);
        assert_eq!(target.pid, None);
    }

    /// Test UprobeTarget parsing - hex offset
    #[test]
    fn test_uprobe_target_hex_offset() {
        let target = UprobeTarget::parse("/lib/libc.so.6:0x12345").unwrap();
        assert_eq!(target.binary_path, "/lib/libc.so.6");
        assert_eq!(target.function_name, None);
        assert_eq!(target.offset, 0x12345);
        assert_eq!(target.pid, None);
    }

    /// Test UprobeTarget parsing - function plus offset
    #[test]
    fn test_uprobe_target_function_plus_offset() {
        let target = UprobeTarget::parse("/usr/bin/app:main+0x10").unwrap();
        assert_eq!(target.binary_path, "/usr/bin/app");
        assert_eq!(target.function_name, Some("main".to_string()));
        assert_eq!(target.offset, 0x10);
        assert_eq!(target.pid, None);
    }

    /// Test UprobeTarget parsing - with PID
    #[test]
    fn test_uprobe_target_with_pid() {
        let target = UprobeTarget::parse("/usr/bin/python:Py_Initialize@1234").unwrap();
        assert_eq!(target.binary_path, "/usr/bin/python");
        assert_eq!(target.function_name, Some("Py_Initialize".to_string()));
        assert_eq!(target.offset, 0);
        assert_eq!(target.pid, Some(1234));
    }

    /// Test UprobeTarget parsing - full specification with offset and PID
    #[test]
    fn test_uprobe_target_full_spec() {
        let target = UprobeTarget::parse("/lib/libc.so.6:malloc+0x20@5678").unwrap();
        assert_eq!(target.binary_path, "/lib/libc.so.6");
        assert_eq!(target.function_name, Some("malloc".to_string()));
        assert_eq!(target.offset, 0x20);
        assert_eq!(target.pid, Some(5678));
    }

    /// Test UprobeTarget parsing - invalid (no colon)
    #[test]
    fn test_uprobe_target_invalid_no_colon() {
        let result = UprobeTarget::parse("/usr/bin/python");
        assert!(result.is_err(), "Expected error for uprobe without colon");
    }

    /// Test UprobeTarget parsing - invalid (empty path)
    #[test]
    fn test_uprobe_target_invalid_empty_path() {
        let result = UprobeTarget::parse(":function");
        assert!(result.is_err(), "Expected error for empty binary path");
    }

    /// Test EbpfState creation and listing
    #[test]
    fn test_ebpf_state_new() {
        use nu_plugin_ebpf::loader::EbpfState;

        let state = EbpfState::new();
        let probes = state.list().expect("list() should succeed");
        assert!(probes.is_empty(), "New state should have no probes");
    }

    /// Test detach returns error for non-existent probe
    #[test]
    fn test_detach_nonexistent_probe() {
        use nu_plugin_ebpf::loader::EbpfState;

        let state = EbpfState::new();
        let result = state.detach(999);
        assert!(result.is_err(), "Detaching non-existent probe should error");

        match result {
            Err(LoadError::ProbeNotFound(id)) => assert_eq!(id, 999),
            Err(e) => panic!("Expected ProbeNotFound error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }
}

/// Tests that don't require Linux
mod common_tests {
    /// Verify module structure compiles correctly
    #[test]
    fn test_module_compiles() {
        // If this test runs, the module compiled successfully
        assert!(true);
    }
}
