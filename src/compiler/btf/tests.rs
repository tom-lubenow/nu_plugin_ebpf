use super::*;

#[test]
fn test_btf_builder() {
    let btf = generate_perf_map_btf("events");

    // Check magic
    assert_eq!(&btf[0..2], &BTF_MAGIC.to_le_bytes());

    // Check version
    assert_eq!(btf[2], BTF_VERSION);

    // Should have reasonable size
    assert!(btf.len() > 24); // At least header size
}

#[test]
fn test_btf_int() {
    let mut btf = BtfBuilder::new();
    let type_id = btf.add_int("int", 4, true);
    assert_eq!(type_id, 1); // First type after void

    let data = btf.build();
    assert!(!data.is_empty());
}

#[test]
fn test_btf_fwd_and_type_tag() {
    let mut btf = BtfBuilder::new();
    let fwd = btf.add_fwd("task_struct", false);
    let tagged = btf.add_type_tag("__kptr", fwd);
    let ptr = btf.add_ptr(tagged);

    assert_eq!(fwd, 1);
    assert_eq!(tagged, 2);
    assert_eq!(ptr, 3);

    let data = btf.build();
    assert!(
        data.windows(b"task_struct\0".len())
            .any(|w| w == b"task_struct\0")
    );
    assert!(data.windows(b"__kptr\0".len()).any(|w| w == b"__kptr\0"));
}
