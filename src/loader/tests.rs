
use super::*;

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
fn test_parse_probe_spec_uretprobe() {
    let (prog_type, target) = parse_probe_spec("uretprobe:/lib/libc.so.6:malloc").unwrap();
    assert!(matches!(prog_type, EbpfProgramType::Uretprobe));
    assert_eq!(target, "/lib/libc.so.6:malloc");
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
fn test_structured_event_string_respects_field_size() {
    let schema = EventSchema {
        fields: vec![
            crate::compiler::SchemaField {
                name: "msg".to_string(),
                field_type: BpfFieldType::String,
                offset: 0,
            },
            crate::compiler::SchemaField {
                name: "value".to_string(),
                field_type: BpfFieldType::Int,
                offset: 24,
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
