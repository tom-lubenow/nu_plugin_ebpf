//! Integration tests for nu_plugin_ebpf commands
//!
//! These tests verify the plugin's functionality at the command level.
//! Tests that require elevated privileges are skipped when not running as root.

#[cfg(target_os = "linux")]
mod linux_tests {
    use nu_plugin_ebpf::loader::{parse_probe_spec, LoadError, UprobeTarget};

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
