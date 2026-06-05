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

#[test]
fn test_btf_decl_tag() {
    let mut btf = BtfBuilder::new();
    let u64_ty = btf.add_int("u64", 8, false);
    let root_ty = btf.add_struct_with_offsets("map_value", 8, &[("head", u64_ty, 0)]);
    let tag_ty = btf.add_decl_tag("contains:node_data:node", root_ty, 0);

    assert_eq!(u64_ty, 1);
    assert_eq!(root_ty, 2);
    assert_eq!(tag_ty, 3);

    let data = btf.build();
    assert!(
        data.windows(b"contains:node_data:node\0".len())
            .any(|w| w == b"contains:node_data:node\0")
    );
}

#[test]
fn test_btf_builder_rejects_struct_member_count_overflow() {
    let mut btf = BtfBuilder::new();
    let int_ty = btf.add_int("int", 4, true);
    let members = vec![("field", int_ty); usize::from(u16::MAX) + 1];

    btf.add_btf_map_struct(&members);

    let err = btf
        .try_build()
        .expect_err("BTF vlen overflow should be rejected");
    assert!(err.contains("vlen"), "expected vlen error, got {err:?}");
}

#[test]
fn test_btf_builder_rejects_struct_size_overflow() {
    let mut btf = BtfBuilder::new();
    let int_ty = btf.add_int("int", 4, true);

    btf.add_struct(
        "too_large",
        &[("first", int_ty, u32::MAX), ("second", int_ty, 1)],
    );

    let err = btf
        .try_build()
        .expect_err("BTF struct size overflow should be rejected");
    assert!(err.contains("size"), "expected size error, got {err:?}");
}
