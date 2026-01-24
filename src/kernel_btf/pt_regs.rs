//! pt_regs offsets resolved from kernel BTF, with fallbacks for common arches.

use std::fmt;

use btf::btf::{Btf, StructMember, Type};

#[derive(Clone, Copy, Debug)]
pub struct PtRegsOffsets {
    pub arg_offsets: [i16; 6],
    pub retval_offset: i16,
}

#[derive(Clone, Debug)]
pub struct PtRegsError {
    pub message: String,
}

impl PtRegsError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PtRegsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PtRegsError {}

#[derive(Clone, Debug)]
struct PtRegsMember {
    name: String,
    offset_bits: u32,
}

#[derive(Clone, Debug)]
struct PtRegsArray {
    offset_bits: u32,
    elem_size_bytes: u32,
    len: u32,
}

pub fn offsets_from_btf(btf: &Btf) -> Result<PtRegsOffsets, PtRegsError> {
    let pt_regs = btf
        .get_type_by_name("pt_regs")
        .or_else(|_| btf.get_type_by_name("user_pt_regs"))
        .map_err(|e| PtRegsError::new(format!("pt_regs type not found: {e}")))?;

    let members = match &pt_regs.base_type {
        Type::Struct(s) | Type::Union(s) => &s.members,
        other => {
            return Err(PtRegsError::new(format!(
                "pt_regs is not a struct/union (got {:?})",
                other
            )));
        }
    };

    let mut simple_members = Vec::with_capacity(members.len());
    let mut regs_array: Option<PtRegsArray> = None;

    for member in members {
        let Some(name) = &member.name else { continue };
        simple_members.push(PtRegsMember {
            name: name.clone(),
            offset_bits: member.offset,
        });
        if name == "regs" {
            regs_array = Some(extract_regs_array(member, btf)?);
        }
    }

    compute_pt_regs_offsets(&simple_members, regs_array)
}

pub fn fallback_offsets() -> Option<PtRegsOffsets> {
    fallback_offsets_inner()
}

fn extract_regs_array(member: &StructMember, btf: &Btf) -> Result<PtRegsArray, PtRegsError> {
    let array_type = btf
        .get_type_by_id(member.type_id)
        .map_err(|e| PtRegsError::new(format!("pt_regs.regs type not found: {e}")))?;

    let Type::Array(array) = &array_type.base_type else {
        return Err(PtRegsError::new(
            "pt_regs.regs is not an array type".to_string(),
        ));
    };

    let elem_type = btf
        .get_type_by_id(array.elem_type_id)
        .map_err(|e| PtRegsError::new(format!("pt_regs.regs elem type not found: {e}")))?;

    let elem_bits = elem_type.bits;
    if elem_bits == 0 {
        return Err(PtRegsError::new(
            "pt_regs.regs element has zero size".to_string(),
        ));
    }
    let elem_size_bytes = elem_bits.div_ceil(8);

    Ok(PtRegsArray {
        offset_bits: member.offset,
        elem_size_bytes,
        len: array.num_elements,
    })
}

fn compute_pt_regs_offsets(
    members: &[PtRegsMember],
    regs_array: Option<PtRegsArray>,
) -> Result<PtRegsOffsets, PtRegsError> {
    let lookup = |names: &[&str]| -> Option<u32> {
        members
            .iter()
            .find(|m| names.iter().any(|n| *n == m.name))
            .map(|m| m.offset_bits)
    };

    let x86_names: [&[&str]; 6] = [
        &["di", "rdi"],
        &["si", "rsi"],
        &["dx", "rdx"],
        &["cx", "rcx"],
        &["r8"],
        &["r9"],
    ];
    let ret_names = ["ax", "rax"];

    if let (
        Some(retval_bits),
        Some(arg0_bits),
        Some(arg1_bits),
        Some(arg2_bits),
        Some(arg3_bits),
        Some(arg4_bits),
        Some(arg5_bits),
    ) = (
        lookup(&ret_names),
        lookup(x86_names[0]),
        lookup(x86_names[1]),
        lookup(x86_names[2]),
        lookup(x86_names[3]),
        lookup(x86_names[4]),
        lookup(x86_names[5]),
    ) {
        return Ok(PtRegsOffsets {
            arg_offsets: [
                bits_to_i16(arg0_bits, "arg0")?,
                bits_to_i16(arg1_bits, "arg1")?,
                bits_to_i16(arg2_bits, "arg2")?,
                bits_to_i16(arg3_bits, "arg3")?,
                bits_to_i16(arg4_bits, "arg4")?,
                bits_to_i16(arg5_bits, "arg5")?,
            ],
            retval_offset: bits_to_i16(retval_bits, "retval")?,
        });
    }

    if let Some(regs) = regs_array {
        if regs.len < 6 {
            return Err(PtRegsError::new(
                "pt_regs.regs has fewer than 6 elements".to_string(),
            ));
        }
        let base = bits_to_i32(regs.offset_bits, "regs base")?;
        let elem = i32::try_from(regs.elem_size_bytes)
            .map_err(|_| PtRegsError::new("pt_regs.regs element size too large".to_string()))?;

        let mut arg_offsets = [0i16; 6];
        for (idx, slot) in arg_offsets.iter_mut().enumerate() {
            let offset = base + (elem * idx as i32);
            *slot = i16::try_from(offset)
                .map_err(|_| PtRegsError::new("pt_regs.regs offset out of range".to_string()))?;
        }

        let retval_offset = i16::try_from(base)
            .map_err(|_| PtRegsError::new("pt_regs.regs base out of range".to_string()))?;

        return Ok(PtRegsOffsets {
            arg_offsets,
            retval_offset,
        });
    }

    Err(PtRegsError::new(
        "pt_regs argument offsets not found in BTF".to_string(),
    ))
}

fn bits_to_i16(bits: u32, label: &str) -> Result<i16, PtRegsError> {
    let bytes = bits_to_i32(bits, label)?;
    i16::try_from(bytes)
        .map_err(|_| PtRegsError::new(format!("pt_regs {label} offset out of range")))
}

fn bits_to_i32(bits: u32, label: &str) -> Result<i32, PtRegsError> {
    if !bits.is_multiple_of(8) {
        return Err(PtRegsError::new(format!(
            "pt_regs {label} offset not byte-aligned"
        )));
    }
    Ok((bits / 8) as i32)
}

#[cfg(target_arch = "x86_64")]
fn fallback_offsets_inner() -> Option<PtRegsOffsets> {
    Some(PtRegsOffsets {
        arg_offsets: [112, 104, 96, 88, 72, 64],
        retval_offset: 80,
    })
}

#[cfg(target_arch = "aarch64")]
fn fallback_offsets_inner() -> Option<PtRegsOffsets> {
    Some(PtRegsOffsets {
        arg_offsets: [0, 8, 16, 24, 32, 40],
        retval_offset: 0,
    })
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn fallback_offsets_inner() -> Option<PtRegsOffsets> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_member_mapping() {
        let members = vec![
            PtRegsMember {
                name: "di".to_string(),
                offset_bits: 112 * 8,
            },
            PtRegsMember {
                name: "si".to_string(),
                offset_bits: 104 * 8,
            },
            PtRegsMember {
                name: "dx".to_string(),
                offset_bits: 96 * 8,
            },
            PtRegsMember {
                name: "cx".to_string(),
                offset_bits: 88 * 8,
            },
            PtRegsMember {
                name: "r8".to_string(),
                offset_bits: 72 * 8,
            },
            PtRegsMember {
                name: "r9".to_string(),
                offset_bits: 64 * 8,
            },
            PtRegsMember {
                name: "ax".to_string(),
                offset_bits: 80 * 8,
            },
        ];

        let offsets = compute_pt_regs_offsets(&members, None).unwrap();
        assert_eq!(offsets.arg_offsets, [112, 104, 96, 88, 72, 64]);
        assert_eq!(offsets.retval_offset, 80);
    }

    #[test]
    fn test_aarch64_regs_array_mapping() {
        let members = vec![PtRegsMember {
            name: "regs".to_string(),
            offset_bits: 0,
        }];
        let regs_array = PtRegsArray {
            offset_bits: 0,
            elem_size_bytes: 8,
            len: 31,
        };

        let offsets = compute_pt_regs_offsets(&members, Some(regs_array)).unwrap();
        assert_eq!(offsets.arg_offsets, [0, 8, 16, 24, 32, 40]);
        assert_eq!(offsets.retval_offset, 0);
    }
}
