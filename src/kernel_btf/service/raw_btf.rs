use std::collections::HashMap;

use btf::Btf;

use super::KfuncRetShape;

#[derive(Clone, Copy)]
pub(super) enum BtfEndianness {
    Little,
    Big,
}

pub(super) fn infer_kfunc_ret_shape(btf: &Btf, ret_type_id: u32) -> KfuncRetShape {
    if ret_type_id == 0 {
        return KfuncRetShape::Void;
    }
    if btf
        .get_type_by_id(ret_type_id)
        .is_ok_and(|ret_ty| ret_ty.num_refs > 0)
    {
        return KfuncRetShape::PointerMaybeNull;
    }
    KfuncRetShape::Scalar
}

fn parse_function_and_proto_return_type_ids_from_raw_btf(
    raw: &[u8],
) -> Option<(HashMap<u32, u32>, HashMap<u32, u32>)> {
    let endianness = detect_btf_endianness(raw)?;
    let hdr_len = read_u32(raw, 4, endianness)?;
    let type_off = read_u32(raw, 8, endianness)?;
    let type_len = read_u32(raw, 12, endianness)?;

    let type_start = hdr_len.checked_add(type_off)?;
    let type_end = type_start.checked_add(type_len)?;
    if type_end as usize > raw.len() {
        return None;
    }

    let mut func_to_proto: HashMap<u32, u32> = HashMap::new();
    let mut proto_to_ret: HashMap<u32, u32> = HashMap::new();
    let mut type_id: u32 = 1;
    let mut cursor: u32 = type_start;

    while cursor < type_end {
        let header_end = cursor.checked_add(12)?;
        if header_end > type_end {
            return None;
        }
        let info = read_u32(raw, cursor as usize + 4, endianness)?;
        let size_type = read_u32(raw, cursor as usize + 8, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        if kind == 12 {
            // BTF_KIND_FUNC: size_type is function prototype type ID.
            func_to_proto.insert(type_id, size_type);
        } else if kind == 13 {
            // BTF_KIND_FUNC_PROTO: size_type is return type ID.
            proto_to_ret.insert(type_id, size_type);
        }

        let payload_len = btf_kind_payload_len(kind, vlen)?;
        cursor = header_end.checked_add(payload_len)?;
        if cursor > type_end {
            return None;
        }
        type_id = type_id.checked_add(1)?;
    }

    if cursor != type_end {
        return None;
    }

    let mut func_to_ret = HashMap::with_capacity(func_to_proto.len());
    for (func_type_id, proto_type_id) in func_to_proto {
        if let Some(ret_type_id) = proto_to_ret.get(&proto_type_id).copied() {
            func_to_ret.insert(func_type_id, ret_type_id);
        }
    }
    Some((func_to_ret, proto_to_ret))
}

pub(super) fn parse_function_return_type_ids_from_raw_btf(raw: &[u8]) -> Option<HashMap<u32, u32>> {
    let (func_to_ret, _) = parse_function_and_proto_return_type_ids_from_raw_btf(raw)?;
    Some(func_to_ret)
}

pub(super) fn parse_function_proto_return_type_ids_from_raw_btf(
    raw: &[u8],
) -> Option<HashMap<u32, u32>> {
    let (_, proto_to_ret) = parse_function_and_proto_return_type_ids_from_raw_btf(raw)?;
    Some(proto_to_ret)
}

pub(super) fn parse_declared_type_sizes_from_raw_btf(raw: &[u8]) -> Option<HashMap<u32, u32>> {
    let endianness = detect_btf_endianness(raw)?;
    let hdr_len = read_u32(raw, 4, endianness)?;
    let type_off = read_u32(raw, 8, endianness)?;
    let type_len = read_u32(raw, 12, endianness)?;

    let type_start = hdr_len.checked_add(type_off)?;
    let type_end = type_start.checked_add(type_len)?;
    if type_end as usize > raw.len() {
        return None;
    }

    let mut out = HashMap::new();
    let mut type_id: u32 = 1;
    let mut cursor: u32 = type_start;

    while cursor < type_end {
        let header_end = cursor.checked_add(12)?;
        if header_end > type_end {
            return None;
        }
        let info = read_u32(raw, cursor as usize + 4, endianness)?;
        let size_type = read_u32(raw, cursor as usize + 8, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        if matches!(kind, 4 | 5) {
            out.insert(type_id, size_type);
        }

        let payload_len = btf_kind_payload_len(kind, vlen)?;
        cursor = header_end.checked_add(payload_len)?;
        if cursor > type_end {
            return None;
        }
        type_id = type_id.checked_add(1)?;
    }

    if cursor != type_end {
        return None;
    }

    Some(out)
}

pub(super) fn parse_pointer_target_type_ids_from_raw_btf(raw: &[u8]) -> Option<HashMap<u32, u32>> {
    let endianness = detect_btf_endianness(raw)?;
    let hdr_len = read_u32(raw, 4, endianness)?;
    let type_off = read_u32(raw, 8, endianness)?;
    let type_len = read_u32(raw, 12, endianness)?;

    let type_start = hdr_len.checked_add(type_off)?;
    let type_end = type_start.checked_add(type_len)?;
    if type_end as usize > raw.len() {
        return None;
    }

    let mut out = HashMap::new();
    let mut type_id: u32 = 1;
    let mut cursor: u32 = type_start;

    while cursor < type_end {
        let header_end = cursor.checked_add(12)?;
        if header_end > type_end {
            return None;
        }
        let info = read_u32(raw, cursor as usize + 4, endianness)?;
        let size_type = read_u32(raw, cursor as usize + 8, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        if kind == 2 {
            out.insert(type_id, size_type);
        }

        let payload_len = btf_kind_payload_len(kind, vlen)?;
        cursor = header_end.checked_add(payload_len)?;
        if cursor > type_end {
            return None;
        }
        type_id = type_id.checked_add(1)?;
    }

    if cursor != type_end {
        return None;
    }

    Some(out)
}

fn detect_btf_endianness(raw: &[u8]) -> Option<BtfEndianness> {
    if raw.len() < 2 {
        return None;
    }
    let magic_le = u16::from_le_bytes([raw[0], raw[1]]);
    if magic_le == 0xeb9f {
        return Some(BtfEndianness::Little);
    }
    let magic_be = u16::from_be_bytes([raw[0], raw[1]]);
    if magic_be == 0xeb9f {
        return Some(BtfEndianness::Big);
    }
    None
}

fn read_u32(raw: &[u8], offset: usize, endianness: BtfEndianness) -> Option<u32> {
    let bytes = raw.get(offset..offset.checked_add(4)?)?;
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(match endianness {
        BtfEndianness::Little => u32::from_le_bytes(arr),
        BtfEndianness::Big => u32::from_be_bytes(arr),
    })
}

fn btf_kind_payload_len(kind: u32, vlen: u32) -> Option<u32> {
    match kind {
        1 => Some(4),                    // BTF_KIND_INT
        2 => Some(0),                    // BTF_KIND_PTR
        3 => Some(12),                   // BTF_KIND_ARRAY
        4 | 5 => vlen.checked_mul(12),   // BTF_KIND_STRUCT / UNION
        6 => vlen.checked_mul(8),        // BTF_KIND_ENUM
        7 => Some(0),                    // BTF_KIND_FWD
        8 | 9 | 10 | 11 | 12 => Some(0), // TYPEDEF / VOLATILE / CONST / RESTRICT / FUNC
        13 => vlen.checked_mul(8),       // BTF_KIND_FUNC_PROTO
        14 => Some(4),                   // BTF_KIND_VAR
        15 => vlen.checked_mul(12),      // BTF_KIND_DATASEC
        16 => Some(0),                   // BTF_KIND_FLOAT
        17 => Some(4),                   // BTF_KIND_DECL_TAG
        18 => Some(0),                   // BTF_KIND_TYPE_TAG
        19 => vlen.checked_mul(12),      // BTF_KIND_ENUM64
        _ => None,
    }
}
