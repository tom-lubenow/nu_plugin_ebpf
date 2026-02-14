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
