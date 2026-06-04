use super::*;
use crate::compiler::mir::{BinOpKind, UnaryOpKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitsNotMode {
    Signed,
    Auto,
    Masked { mask: i64 },
}

const BITS_NOT_UNSIGNED_I64_MASK: i64 = 0x7fff_ffff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitsShiftMode {
    SignedI64,
    UnsignedI64,
    FixedWidth { bits: i64, mask: i64, sign_bit: i64 },
    SignedFixedWidth { bits: i64, mask: i64, sign_bit: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitsBinaryEndian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BitsShiftSpec {
    count: i64,
    mode: BitsShiftMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BitsRotateSpec {
    count: i64,
    mode: BitsShiftMode,
}

impl<'a> HirToMirLowering<'a> {
    fn bits_binary_op(cmd_name: &str) -> BinOpKind {
        match cmd_name {
            "bits and" => BinOpKind::And,
            "bits or" => BinOpKind::Or,
            "bits xor" => BinOpKind::Xor,
            _ => unreachable!("validated bits binary command"),
        }
    }

    fn bits_binary_output(cmd_name: &str, lhs: i64, rhs: i64) -> i64 {
        match cmd_name {
            "bits and" => lhs & rhs,
            "bits or" => lhs | rhs,
            "bits xor" => lhs ^ rhs,
            _ => unreachable!("validated bits binary command"),
        }
    }

    fn bits_binary_byte_output(cmd_name: &str, lhs: u8, rhs: u8) -> u8 {
        match cmd_name {
            "bits and" => lhs & rhs,
            "bits or" => lhs | rhs,
            "bits xor" => lhs ^ rhs,
            _ => unreachable!("validated bits binary command"),
        }
    }

    fn bits_binary_bytes_output(
        cmd_name: &str,
        lhs: &[u8],
        rhs: &[u8],
        endian: BitsBinaryEndian,
    ) -> Vec<u8> {
        let len = lhs.len().max(rhs.len());
        let mut output = Vec::with_capacity(len);
        match endian {
            BitsBinaryEndian::Little => {
                for index in 0..len {
                    let lhs_byte = lhs.get(index).copied().unwrap_or(0);
                    let rhs_byte = rhs.get(index).copied().unwrap_or(0);
                    output.push(Self::bits_binary_byte_output(cmd_name, lhs_byte, rhs_byte));
                }
            }
            BitsBinaryEndian::Big => {
                let lhs_padding = len.saturating_sub(lhs.len());
                let rhs_padding = len.saturating_sub(rhs.len());
                for index in 0..len {
                    let lhs_byte = index
                        .checked_sub(lhs_padding)
                        .and_then(|lhs_index| lhs.get(lhs_index))
                        .copied()
                        .unwrap_or(0);
                    let rhs_byte = index
                        .checked_sub(rhs_padding)
                        .and_then(|rhs_index| rhs.get(rhs_index))
                        .copied()
                        .unwrap_or(0);
                    output.push(Self::bits_binary_byte_output(cmd_name, lhs_byte, rhs_byte));
                }
            }
        }
        output
    }

    fn bits_not_binary_bytes_output(input: &[u8]) -> Vec<u8> {
        input.iter().map(|byte| !byte).collect()
    }

    fn bits_binary_get_bit(input: &[u8], bit_index: usize) -> bool {
        let byte = input[bit_index / 8];
        let mask = 1u8 << (7 - (bit_index % 8));
        byte & mask != 0
    }

    fn bits_binary_set_bit(output: &mut [u8], bit_index: usize) {
        let mask = 1u8 << (7 - (bit_index % 8));
        output[bit_index / 8] |= mask;
    }

    fn bits_binary_shift_rotate_output(
        cmd_name: &str,
        input: &[u8],
        count: usize,
    ) -> Result<Vec<u8>, CompileError> {
        let bit_len = input.len().checked_mul(8).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} binary input is too large to transform in eBPF"
            ))
        })?;
        let count_name = if matches!(cmd_name, "bits shl" | "bits shr") {
            "shift"
        } else {
            "rotate"
        };
        if count > bit_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a {count_name} count from 0 through {bit_len} for binary input in eBPF; got {count}"
            )));
        }

        if bit_len == 0 {
            return Ok(Vec::new());
        }

        let mut output = vec![0u8; input.len()];
        let rotate = count % bit_len;
        for out_bit in 0..bit_len {
            let src_bit = match cmd_name {
                "bits shl" => (out_bit + count < bit_len).then_some(out_bit + count),
                "bits shr" => out_bit.checked_sub(count),
                "bits rol" => Some((out_bit + rotate) % bit_len),
                "bits ror" => Some((out_bit + bit_len - rotate) % bit_len),
                _ => unreachable!("validated bits shift/rotate command"),
            };
            if let Some(src_bit) = src_bit {
                if Self::bits_binary_get_bit(input, src_bit) {
                    Self::bits_binary_set_bit(&mut output, out_bit);
                }
            }
        }
        Ok(output)
    }

    fn bits_shift_op(cmd_name: &str, mode: BitsShiftMode) -> BinOpKind {
        match cmd_name {
            "bits shl" => BinOpKind::Shl,
            "bits shr" => match mode {
                BitsShiftMode::SignedI64 => BinOpKind::ArShr,
                BitsShiftMode::UnsignedI64
                | BitsShiftMode::FixedWidth { .. }
                | BitsShiftMode::SignedFixedWidth { .. } => BinOpKind::Shr,
            },
            _ => unreachable!("validated bits shift command"),
        }
    }

    fn bits_shift_output(
        cmd_name: &str,
        lhs: i64,
        spec: BitsShiftSpec,
    ) -> Result<i64, CompileError> {
        debug_assert!(spec.count >= 0);
        let shift = spec.count as u32;
        match spec.mode {
            BitsShiftMode::SignedI64 => {
                debug_assert!(spec.count < 64);
                Ok(match cmd_name {
                    "bits shl" => lhs.wrapping_shl(shift),
                    "bits shr" => lhs >> shift,
                    _ => unreachable!("validated bits shift command"),
                })
            }
            BitsShiftMode::UnsignedI64 => {
                debug_assert!(spec.count < 64);
                if lhs < 0 {
                    return Ok(match cmd_name {
                        "bits shl" => lhs.wrapping_shl(shift),
                        "bits shr" => lhs >> shift,
                        _ => unreachable!("validated bits shift command"),
                    });
                }

                let output = match cmd_name {
                    "bits shl" => (lhs as u64) << shift,
                    "bits shr" => (lhs as u64) >> shift,
                    _ => unreachable!("validated bits shift command"),
                };
                i64::try_from(output).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} unsigned 8-byte output exceeds Nushell's integer range in eBPF; use --signed --number-bytes 8 for signed two's-complement output"
                    ))
                })
            }
            BitsShiftMode::FixedWidth { mask, sign_bit, .. } => {
                let truncated = lhs & mask;
                Ok(if lhs < 0 {
                    match cmd_name {
                        "bits shl" => {
                            let shifted = (truncated << shift) & mask;
                            Self::sign_extend_width(shifted, sign_bit)
                        }
                        "bits shr" => {
                            let signed = Self::sign_extend_width(truncated, sign_bit);
                            signed >> shift
                        }
                        _ => unreachable!("validated bits shift command"),
                    }
                } else {
                    match cmd_name {
                        "bits shl" => (truncated << shift) & mask,
                        "bits shr" => truncated >> shift,
                        _ => unreachable!("validated bits shift command"),
                    }
                })
            }
            BitsShiftMode::SignedFixedWidth { mask, sign_bit, .. } => {
                let truncated = lhs & mask;
                let signed = Self::sign_extend_width(truncated, sign_bit);
                Ok(match cmd_name {
                    "bits shl" => {
                        let shifted = (signed << shift) & mask;
                        Self::sign_extend_width(shifted, sign_bit)
                    }
                    "bits shr" => signed >> shift,
                    _ => unreachable!("validated bits shift command"),
                })
            }
        }
    }

    fn sign_extend_width(value: i64, sign_bit: i64) -> i64 {
        (value ^ sign_bit) - sign_bit
    }

    fn bits_rotate_output(
        cmd_name: &str,
        lhs: i64,
        spec: BitsRotateSpec,
    ) -> Result<i64, CompileError> {
        debug_assert!(spec.count >= 0);
        match spec.mode {
            BitsShiftMode::SignedI64 => {
                debug_assert!(spec.count <= 64);
                let rotate = spec.count as u32;
                Ok(match cmd_name {
                    "bits rol" => lhs.rotate_left(rotate),
                    "bits ror" => lhs.rotate_right(rotate),
                    _ => unreachable!("validated bits rotate command"),
                })
            }
            BitsShiftMode::UnsignedI64 => {
                debug_assert!(spec.count <= 64);
                if lhs < 0 {
                    let rotate = spec.count as u32;
                    return Ok(match cmd_name {
                        "bits rol" => lhs.rotate_left(rotate),
                        "bits ror" => lhs.rotate_right(rotate),
                        _ => unreachable!("validated bits rotate command"),
                    });
                }

                let rotate = (spec.count % 64) as u32;
                let output = match cmd_name {
                    "bits rol" => (lhs as u64).rotate_left(rotate),
                    "bits ror" => (lhs as u64).rotate_right(rotate),
                    _ => unreachable!("validated bits rotate command"),
                };
                i64::try_from(output).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} unsigned 8-byte output exceeds Nushell's integer range in eBPF; use --signed --number-bytes 8 for signed two's-complement output"
                    ))
                })
            }
            BitsShiftMode::FixedWidth {
                bits,
                mask,
                sign_bit,
            } => {
                let truncated = lhs & mask;
                let rotate = (spec.count % bits) as u32;
                let width = bits as u32;
                let rotated = if rotate == 0 {
                    truncated
                } else {
                    match cmd_name {
                        "bits rol" => {
                            ((truncated << rotate) | (truncated >> (width - rotate))) & mask
                        }
                        "bits ror" => {
                            ((truncated >> rotate) | (truncated << (width - rotate))) & mask
                        }
                        _ => unreachable!("validated bits rotate command"),
                    }
                };
                if lhs < 0 {
                    Ok(Self::sign_extend_width(rotated, sign_bit))
                } else {
                    Ok(rotated)
                }
            }
            BitsShiftMode::SignedFixedWidth {
                bits,
                mask,
                sign_bit,
            } => {
                let truncated = lhs & mask;
                let rotate = (spec.count % bits) as u32;
                let width = bits as u32;
                let rotated = if rotate == 0 {
                    truncated
                } else {
                    match cmd_name {
                        "bits rol" => {
                            ((truncated << rotate) | (truncated >> (width - rotate))) & mask
                        }
                        "bits ror" => {
                            ((truncated >> rotate) | (truncated << (width - rotate))) & mask
                        }
                        _ => unreachable!("validated bits rotate command"),
                    }
                };
                Ok(Self::sign_extend_width(rotated, sign_bit))
            }
        }
    }

    fn bits_integer_value_from_metadata(meta: &RegMetadata) -> Option<i64> {
        meta.literal_int
            .or_else(|| match meta.constant_value.as_ref() {
                Some(nu_protocol::Value::Int { val, .. }) => Some(*val),
                _ => None,
            })
    }

    fn bits_binary_endian(&self, cmd_name: &str) -> Result<BitsBinaryEndian, CompileError> {
        if !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not support parser-info arguments in eBPF"
            )));
        }
        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} supports only --endian for binary input in eBPF"
            )));
        }

        let mut endian_reg = None;
        for (name, (_vreg, reg)) in &self.named_args {
            match name.as_str() {
                "endian" | "e" => {
                    if endian_reg.replace(*reg).is_some() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} accepts only one --endian argument in eBPF"
                        )));
                    }
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} supports only --endian for binary input in eBPF"
                    )));
                }
            }
        }

        let Some(endian_reg) = endian_reg else {
            return Ok(Self::native_bits_binary_endian());
        };
        let endian = self.literal_string_arg(endian_reg, &format!("{cmd_name} --endian"))?;
        match endian.as_str() {
            "native" => Ok(Self::native_bits_binary_endian()),
            "little" => Ok(BitsBinaryEndian::Little),
            "big" => Ok(BitsBinaryEndian::Big),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} --endian supports only native, little, or big in eBPF; got {endian:?}"
            ))),
        }
    }

    fn native_bits_binary_endian() -> BitsBinaryEndian {
        if cfg!(target_endian = "big") {
            BitsBinaryEndian::Big
        } else {
            BitsBinaryEndian::Little
        }
    }

    fn bits_binary_value_from_metadata(meta: &RegMetadata) -> Option<Vec<u8>> {
        match meta.constant_value.as_ref() {
            Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
            _ => None,
        }
    }

    fn lower_bits_binary_list_output(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        output: Vec<nu_protocol::Value>,
    ) -> Result<(), CompileError> {
        let mut expected_len = None;
        let mut has_empty_output = false;
        let mut has_unequal_output_len = false;
        for value in &output {
            let nu_protocol::Value::Binary { val, .. } = value else {
                unreachable!("validated bits binary-list output");
            };
            if val.is_empty() {
                has_empty_output = true;
            }
            if let Some(expected_len) = expected_len {
                if val.len() != expected_len {
                    has_unequal_output_len = true;
                }
            } else {
                expected_len = Some(val.len());
            }
        }

        let is_empty = output.is_empty();
        if (is_empty || has_empty_output || has_unequal_output_len)
            && !self.current_call_result_metadata_only
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} binary list output requires non-empty equal-length binary items in eBPF"
            )));
        }

        self.reset_call_result_metadata(src_dst);
        let value = nu_protocol::Value::list(output, nu_protocol::Span::unknown());
        if is_empty || has_empty_output || has_unequal_output_len {
            self.lower_compile_time_only_constant_value(src_dst, &value);
        } else {
            self.lower_constant_value(src_dst, &value)?;
        }
        Ok(())
    }

    fn bits_not_signed_flag(&self, cmd_name: &str) -> Result<bool, CompileError> {
        Ok(match self.named_flags.as_slice() {
            [] => false,
            [flag] if matches!(flag.as_str(), "signed" | "s") => true,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} supports only --signed or --number-bytes for integer input in eBPF"
                )));
            }
        })
    }

    fn bits_not_number_bytes_arg(&self, cmd_name: &str) -> Result<Option<i64>, CompileError> {
        let mut number_bytes_reg = None;
        for (name, (_vreg, reg)) in &self.named_args {
            match name.as_str() {
                "number-bytes" | "n" => {
                    if number_bytes_reg.replace(*reg).is_some() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} accepts only one --number-bytes argument in eBPF"
                        )));
                    }
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} supports only --number-bytes for bits-not width control in eBPF"
                    )));
                }
            }
        }

        let Some(reg) = number_bytes_reg else {
            return Ok(None);
        };
        let number_bytes = {
            let meta = self.get_metadata(reg).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                ))
            })?;
            Self::bits_integer_value_from_metadata(meta).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                ))
            })?
        };
        Ok(Some(number_bytes))
    }

    fn bits_not_mode(&self, cmd_name: &str) -> Result<BitsNotMode, CompileError> {
        if !self.positional_args.is_empty() || !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} accepts no positional or parser-info arguments in eBPF"
            )));
        }

        let signed = self.bits_not_signed_flag(cmd_name)?;
        let number_bytes = self.bits_not_number_bytes_arg(cmd_name)?;
        if signed {
            if let Some(number_bytes) = number_bytes {
                if !matches!(number_bytes, 1 | 2 | 4 | 8) {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} --signed supports --number-bytes 1, 2, 4, or 8 in eBPF; got {number_bytes}"
                    )));
                }
            }
            return Ok(BitsNotMode::Signed);
        }

        let Some(number_bytes) = number_bytes else {
            return Ok(BitsNotMode::Auto);
        };

        let mask = match number_bytes {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffff_ffff,
            8 => BITS_NOT_UNSIGNED_I64_MASK,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} masked integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got {number_bytes}"
                )));
            }
        };
        Ok(BitsNotMode::Masked { mask })
    }

    fn validate_bits_not_binary_flags(&self, cmd_name: &str) -> Result<(), CompileError> {
        if !self.positional_args.is_empty() || !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} accepts no positional or parser-info arguments in eBPF"
            )));
        }

        self.bits_not_signed_flag(cmd_name)?;
        if let Some(number_bytes) = self.bits_not_number_bytes_arg(cmd_name)? {
            if !matches!(number_bytes, 1 | 2 | 4 | 8) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got {number_bytes}"
                )));
            }
        }
        Ok(())
    }

    fn bits_not_output(cmd_name: &str, input: i64, mode: BitsNotMode) -> Result<i64, CompileError> {
        match mode {
            BitsNotMode::Signed => Ok(!input),
            BitsNotMode::Auto => Self::bits_not_auto_output(cmd_name, input),
            BitsNotMode::Masked { mask } => Ok(if input < 0 { !input } else { (!input) & mask }),
        }
    }

    fn bits_not_auto_output(_cmd_name: &str, input: i64) -> Result<i64, CompileError> {
        if input < 0 {
            return Ok(!input);
        }

        let mask = match input {
            0..=0xff => 0xff,
            0x100..=0xffff => 0xffff,
            0x1_0000..=0xffff_ffff => 0xffff_ffff,
            _ => BITS_NOT_UNSIGNED_I64_MASK,
        };
        Ok((!input) & mask)
    }

    fn validate_bits_integer_operand(
        &self,
        cmd_name: &str,
        role: &str,
        meta: &RegMetadata,
        vreg: VReg,
    ) -> Result<(), CompileError> {
        if Self::bits_integer_value_from_metadata(meta).is_some() {
            return Ok(());
        }

        let ty = meta
            .field_type
            .as_ref()
            .or_else(|| self.vreg_type_hints.get(&vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compiler-known integer {role} in eBPF"
                ))
            })?;
        if Self::mir_type_is_integer(ty) {
            Ok(())
        } else {
            Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer {role} in eBPF; got MIR type {ty:?}"
            )))
        }
    }

    fn validate_bits_integer_operand_optional_metadata(
        &self,
        cmd_name: &str,
        role: &str,
        meta: Option<&RegMetadata>,
        vreg: VReg,
    ) -> Result<(), CompileError> {
        if let Some(meta) = meta {
            return self.validate_bits_integer_operand(cmd_name, role, meta, vreg);
        }

        let ty = self.vreg_type_hints.get(&vreg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires compiler-known integer {role} in eBPF"
            ))
        })?;
        if Self::mir_type_is_integer(ty) {
            Ok(())
        } else {
            Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer {role} in eBPF; got MIR type {ty:?}"
            )))
        }
    }

    fn bits_fixed_width_mode(number_bytes: i64, signed: bool) -> Option<BitsShiftMode> {
        match (number_bytes, signed) {
            (1, false) => Some(BitsShiftMode::FixedWidth {
                bits: 8,
                mask: 0xff,
                sign_bit: 0x80,
            }),
            (2, false) => Some(BitsShiftMode::FixedWidth {
                bits: 16,
                mask: 0xffff,
                sign_bit: 0x8000,
            }),
            (4, false) => Some(BitsShiftMode::FixedWidth {
                bits: 32,
                mask: 0xffff_ffff,
                sign_bit: 0x8000_0000,
            }),
            (8, false) => Some(BitsShiftMode::UnsignedI64),
            (1, true) => Some(BitsShiftMode::SignedFixedWidth {
                bits: 8,
                mask: 0xff,
                sign_bit: 0x80,
            }),
            (2, true) => Some(BitsShiftMode::SignedFixedWidth {
                bits: 16,
                mask: 0xffff,
                sign_bit: 0x8000,
            }),
            (4, true) => Some(BitsShiftMode::SignedFixedWidth {
                bits: 32,
                mask: 0xffff_ffff,
                sign_bit: 0x8000_0000,
            }),
            (8, true) => Some(BitsShiftMode::SignedI64),
            _ => None,
        }
    }

    fn bits_auto_width_mode(input: i64) -> BitsShiftMode {
        if input < 0 {
            if input >= i8::MIN as i64 {
                BitsShiftMode::FixedWidth {
                    bits: 8,
                    mask: 0xff,
                    sign_bit: 0x80,
                }
            } else if input >= i16::MIN as i64 {
                BitsShiftMode::FixedWidth {
                    bits: 16,
                    mask: 0xffff,
                    sign_bit: 0x8000,
                }
            } else if input >= i32::MIN as i64 {
                BitsShiftMode::FixedWidth {
                    bits: 32,
                    mask: 0xffff_ffff,
                    sign_bit: 0x8000_0000,
                }
            } else {
                BitsShiftMode::SignedI64
            }
        } else if input <= u8::MAX as i64 {
            BitsShiftMode::FixedWidth {
                bits: 8,
                mask: 0xff,
                sign_bit: 0x80,
            }
        } else if input <= u16::MAX as i64 {
            BitsShiftMode::FixedWidth {
                bits: 16,
                mask: 0xffff,
                sign_bit: 0x8000,
            }
        } else if input <= u32::MAX as i64 {
            BitsShiftMode::FixedWidth {
                bits: 32,
                mask: 0xffff_ffff,
                sign_bit: 0x8000_0000,
            }
        } else {
            BitsShiftMode::UnsignedI64
        }
    }

    fn bits_unsigned_i64_left_shift_runtime_limit(ty: &MirType) -> Option<(&'static str, i64)> {
        match ty {
            MirType::U8 => Some(("u8", 55)),
            MirType::U16 => Some(("u16", 47)),
            MirType::U32 => Some(("u32", 31)),
            _ => None,
        }
    }

    fn validate_bits_unsigned_i64_left_shift_runtime_scalar(
        &self,
        cmd_name: &str,
        input_meta: Option<&RegMetadata>,
        input_vreg: VReg,
        shift_count: i64,
    ) -> Result<(), CompileError> {
        let input_ty = input_meta
            .and_then(|meta| meta.field_type.as_ref())
            .or_else(|| self.vreg_type_hints.get(&input_vreg));
        let Some((ty_name, max_count)) =
            input_ty.and_then(Self::bits_unsigned_i64_left_shift_runtime_limit)
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} unsigned --number-bytes 8 requires compile-time known integer input or runtime u8, u16, or u32 input in eBPF; use --signed --number-bytes 8 for generic runtime 64-bit left shifts"
            )));
        };
        if shift_count > max_count {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} unsigned --number-bytes 8 runtime {ty_name} input supports shift counts from 0 through {max_count} in eBPF; got {shift_count}"
            )));
        }
        Ok(())
    }

    fn validate_bits_unsigned_i64_left_rotate_runtime_scalar(
        &self,
        cmd_name: &str,
        input_meta: Option<&RegMetadata>,
        input_vreg: VReg,
        rotate_count: i64,
    ) -> Result<(), CompileError> {
        let input_ty = input_meta
            .and_then(|meta| meta.field_type.as_ref())
            .or_else(|| self.vreg_type_hints.get(&input_vreg));
        let Some((ty_name, max_count)) =
            input_ty.and_then(Self::bits_unsigned_i64_left_shift_runtime_limit)
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} unsigned --number-bytes 8 requires compile-time known integer input or runtime u8, u16, or u32 input in eBPF; use --signed --number-bytes 8 for generic runtime 64-bit rotates"
            )));
        };
        if rotate_count > max_count && rotate_count != 64 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} unsigned --number-bytes 8 runtime {ty_name} input supports rotate counts from 0 through {max_count}, or 64, in eBPF; got {rotate_count}"
            )));
        }
        Ok(())
    }

    fn bits_binary_shift_rotate_count(&self, cmd_name: &str) -> Result<usize, CompileError> {
        if !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not support parser-info arguments in eBPF"
            )));
        }
        if self.positional_args.len() != 1 {
            let count_name = if matches!(cmd_name, "bits shl" | "bits shr") {
                "shift"
            } else {
                "rotate"
            };
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one compile-time {count_name}-count argument in eBPF"
            )));
        }

        match self.named_flags.as_slice() {
            [] => {}
            [flag] if matches!(flag.as_str(), "signed" | "s") => {}
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} supports only --signed and --number-bytes for binary input in eBPF"
                )));
            }
        }

        let mut number_bytes_reg = None;
        for (name, (_vreg, reg)) in &self.named_args {
            match name.as_str() {
                "number-bytes" | "n" => {
                    if number_bytes_reg.replace(*reg).is_some() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} accepts only one --number-bytes argument in eBPF"
                        )));
                    }
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} supports only --number-bytes for binary input in eBPF"
                    )));
                }
            }
        }
        if let Some(number_bytes_reg) = number_bytes_reg {
            let number_bytes_meta = self.get_metadata(number_bytes_reg).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                ))
            })?;
            let Some(number_bytes) = Self::bits_integer_value_from_metadata(number_bytes_meta)
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                )));
            };
            if !matches!(number_bytes, 1 | 2 | 4 | 8) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got {number_bytes}"
                )));
            }
        }

        let count_name = if matches!(cmd_name, "bits shl" | "bits shr") {
            "shift"
        } else {
            "rotate"
        };
        let (_count_vreg, count_reg) = self.positional_args[0];
        let count_meta = self.get_metadata(count_reg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a compile-time integer {count_name} count in eBPF"
            ))
        })?;
        let Some(count) = Self::bits_integer_value_from_metadata(count_meta) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a compile-time integer {count_name} count in eBPF"
            )));
        };
        if count < 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a non-negative {count_name} count in eBPF; got {count}"
            )));
        }
        usize::try_from(count).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} {count_name} count is too large for eBPF binary input: {count}"
            ))
        })
    }

    fn bits_shift_spec(
        &self,
        cmd_name: &str,
        auto_input: Option<i64>,
    ) -> Result<BitsShiftSpec, CompileError> {
        if !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not support parser-info arguments in eBPF"
            )));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one compile-time shift-count argument in eBPF"
            )));
        }

        let signed = match self.named_flags.as_slice() {
            [] => false,
            [flag] if matches!(flag.as_str(), "signed" | "s") => true,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} supports only --signed and --number-bytes for integer input in eBPF"
                )));
            }
        };

        let mut number_bytes_reg = None;
        for (name, (_vreg, reg)) in &self.named_args {
            match name.as_str() {
                "number-bytes" | "n" => {
                    if number_bytes_reg.replace(*reg).is_some() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} accepts only one --number-bytes argument in eBPF"
                        )));
                    }
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} supports only --number-bytes for integer input in eBPF"
                    )));
                }
            }
        }

        let mode = if let Some(number_bytes_reg) = number_bytes_reg {
            let number_bytes_meta = self.get_metadata(number_bytes_reg).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                ))
            })?;
            let Some(number_bytes) = Self::bits_integer_value_from_metadata(number_bytes_meta)
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                )));
            };

            let mode = Self::bits_fixed_width_mode(number_bytes, signed).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got {number_bytes}"
                ))
            })?;
            mode
        } else if signed {
            BitsShiftMode::SignedI64
        } else {
            let Some(input) = auto_input else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} default auto-width shifts require compile-time known integer input in eBPF; use --number-bytes 1, 2, or 4, or --signed --number-bytes 8 for runtime input"
                )));
            };
            Self::bits_auto_width_mode(input)
        };

        let (_shift_vreg, shift_reg) = self.positional_args[0];
        let shift_meta = self.get_metadata(shift_reg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a compile-time integer shift count in eBPF"
            ))
        })?;
        let Some(shift_count) = Self::bits_integer_value_from_metadata(shift_meta) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a compile-time integer shift count in eBPF"
            )));
        };
        let max_count = match mode {
            BitsShiftMode::SignedI64 | BitsShiftMode::UnsignedI64 => 63,
            BitsShiftMode::FixedWidth { bits, .. }
            | BitsShiftMode::SignedFixedWidth { bits, .. } => bits - 1,
        };
        if !(0..=max_count).contains(&shift_count) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a shift count from 0 through {max_count} in eBPF; got {shift_count}"
            )));
        }

        Ok(BitsShiftSpec {
            count: shift_count,
            mode,
        })
    }

    fn bits_rotate_spec(
        &self,
        cmd_name: &str,
        auto_input: Option<i64>,
    ) -> Result<BitsRotateSpec, CompileError> {
        if !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not support parser-info arguments in eBPF"
            )));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one compile-time rotate-count argument in eBPF"
            )));
        }

        let signed = match self.named_flags.as_slice() {
            [] => false,
            [flag] if matches!(flag.as_str(), "signed" | "s") => true,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} supports only --signed and --number-bytes for integer input in eBPF"
                )));
            }
        };

        let mut number_bytes_reg = None;
        for (name, (_vreg, reg)) in &self.named_args {
            match name.as_str() {
                "number-bytes" | "n" => {
                    if number_bytes_reg.replace(*reg).is_some() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} accepts only one --number-bytes argument in eBPF"
                        )));
                    }
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} supports only --number-bytes for integer input in eBPF"
                    )));
                }
            }
        }

        let mode = if let Some(number_bytes_reg) = number_bytes_reg {
            let number_bytes_meta = self.get_metadata(number_bytes_reg).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                ))
            })?;
            let Some(number_bytes) = Self::bits_integer_value_from_metadata(number_bytes_meta)
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compile-time --number-bytes in eBPF"
                )));
            };
            let mode = Self::bits_fixed_width_mode(number_bytes, signed).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got {number_bytes}"
                ))
            })?;
            mode
        } else if signed {
            BitsShiftMode::SignedI64
        } else {
            let Some(input) = auto_input else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} default auto-width rotates require compile-time known integer input in eBPF; use --number-bytes 1, 2, or 4, or --signed --number-bytes 8 for runtime input"
                )));
            };
            Self::bits_auto_width_mode(input)
        };

        let (_rotate_vreg, rotate_reg) = self.positional_args[0];
        let rotate_meta = self.get_metadata(rotate_reg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a compile-time integer rotate count in eBPF"
            ))
        })?;
        let Some(rotate_count) = Self::bits_integer_value_from_metadata(rotate_meta) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a compile-time integer rotate count in eBPF"
            )));
        };
        let max_count = match mode {
            BitsShiftMode::SignedI64 | BitsShiftMode::UnsignedI64 => 64,
            BitsShiftMode::FixedWidth { bits, .. }
            | BitsShiftMode::SignedFixedWidth { bits, .. } => bits,
        };
        if !(0..=max_count).contains(&rotate_count) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a rotate count from 0 through {max_count} in eBPF; got {rotate_count}"
            )));
        }

        Ok(BitsRotateSpec {
            count: rotate_count,
            mode,
        })
    }

    pub(in crate::compiler::ir_to_mir) fn lower_bits_binary(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_BITS_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        let endian = self.bits_binary_endian(cmd_name)?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one integer or binary target argument in eBPF"
            )));
        }

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned();

        let (rhs_vreg, rhs_reg) = self.positional_args[0];
        let rhs_meta = self.get_metadata(rhs_reg).cloned();
        let rhs_const = rhs_meta
            .as_ref()
            .and_then(Self::bits_integer_value_from_metadata);
        let rhs_binary_const = rhs_meta
            .as_ref()
            .and_then(Self::bits_binary_value_from_metadata);
        let op = Self::bits_binary_op(cmd_name);

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            if vals
                .iter()
                .all(|value| matches!(value, nu_protocol::Value::Binary { .. }))
                && (!vals.is_empty() || rhs_binary_const.is_some())
            {
                let Some(rhs_binary) = rhs_binary_const.as_ref() else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires a compile-time binary target argument for binary-list input in eBPF"
                    )));
                };
                let output = vals
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let nu_protocol::Value::Binary { val, .. } = value else {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires binary list items in eBPF; item {index} has type {}",
                                value.get_type()
                            )));
                        };
                        Ok(nu_protocol::Value::binary(
                            Self::bits_binary_bytes_output(cmd_name, &val, rhs_binary, endian),
                            nu_protocol::Span::unknown(),
                        ))
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                return self.lower_bits_binary_list_output(cmd_name, src_dst, output);
            }

            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            self.validate_bits_integer_operand_optional_metadata(
                cmd_name,
                "target argument",
                rhs_meta.as_ref(),
                rhs_vreg,
            )?;
            let Some(rhs) = rhs_const else {
                if let Some(input_meta) = input_meta.as_ref()
                    && input_meta.list_buffer.is_some()
                {
                    // A numeric constant list is also available as a stack-backed
                    // list, so runtime list lowering below can reuse the RHS vreg.
                    return self.lower_bits_binary_runtime_list(
                        cmd_name,
                        src_dst,
                        input_vreg,
                        result_vreg,
                        input_meta,
                        op,
                        MirValue::VReg(rhs_vreg),
                    );
                }
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a compile-time integer target argument for compile-time known list input in eBPF"
                )));
            };
            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let lhs = match value {
                        nu_protocol::Value::Int { val, .. } => val,
                        other => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires integer list items in eBPF; item {index} has type {}",
                                other.get_type()
                            )));
                        }
                    };
                    Ok(nu_protocol::Value::int(
                        Self::bits_binary_output(cmd_name, lhs, rhs),
                        nu_protocol::Span::unknown(),
                    ))
                })
                .collect::<Result<Vec<_>, CompileError>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(input_meta) = input_meta.as_ref()
            && input_meta.list_buffer.is_some()
        {
            self.validate_bits_integer_operand_optional_metadata(
                cmd_name,
                "target argument",
                rhs_meta.as_ref(),
                rhs_vreg,
            )?;
            return self.lower_bits_binary_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                input_meta,
                op,
                rhs_const.map_or(MirValue::VReg(rhs_vreg), MirValue::Const),
            );
        }

        if let Some(nu_protocol::Value::Binary { val, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.as_ref())
        {
            let Some(rhs_binary) = rhs_binary_const.as_ref() else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a compile-time binary target argument for binary input in eBPF"
                )));
            };
            let output = Self::bits_binary_bytes_output(cmd_name, val, rhs_binary, endian);
            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if rhs_binary_const.is_some() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires binary pipeline input when the target argument is binary in eBPF"
            )));
        }

        self.validate_bits_integer_operand_optional_metadata(
            cmd_name,
            "target argument",
            rhs_meta.as_ref(),
            rhs_vreg,
        )?;
        self.validate_bits_integer_operand_optional_metadata(
            cmd_name,
            "pipeline input",
            input_meta.as_ref(),
            input_vreg,
        )?;
        let rhs_value = rhs_const.map_or(MirValue::VReg(rhs_vreg), MirValue::Const);
        let lhs_const = input_meta
            .as_ref()
            .and_then(Self::bits_integer_value_from_metadata);
        let lhs_value = lhs_const.map_or(MirValue::VReg(input_vreg), MirValue::Const);
        let constant_output = match (lhs_const, rhs_const) {
            (Some(lhs), Some(rhs)) => Some(Self::bits_binary_output(cmd_name, lhs, rhs)),
            _ => None,
        };

        if let Some(output) = constant_output {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(output),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = Some(nu_protocol::Value::int(
                output,
                nu_protocol::Span::unknown(),
            ));
            out_meta.literal_int = Some(output);
        } else {
            self.emit(MirInst::BinOp {
                dst: result_vreg,
                op,
                lhs: lhs_value,
                rhs: rhs_value,
            });
            self.reset_call_result_metadata(src_dst);
            self.get_or_create_metadata(src_dst).field_type = Some(MirType::I64);
        }
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn lower_bits_shift(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_BITS_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned();

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            if !vals.is_empty()
                && vals
                    .iter()
                    .all(|value| matches!(value, nu_protocol::Value::Binary { .. }))
            {
                let count = self.bits_binary_shift_rotate_count(cmd_name)?;
                let output = vals
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let nu_protocol::Value::Binary { val, .. } = value else {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires binary list items in eBPF; item {index} has type {}",
                                value.get_type()
                            )));
                        };
                        Ok(nu_protocol::Value::binary(
                            Self::bits_binary_shift_rotate_output(cmd_name, &val, count)?,
                            nu_protocol::Span::unknown(),
                        ))
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                return self.lower_bits_binary_list_output(cmd_name, src_dst, output);
            }

            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let lhs = match value {
                        nu_protocol::Value::Int { val, .. } => val,
                        other => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires integer list items in eBPF; item {index} has type {}",
                                other.get_type()
                            )));
                        }
                    };
                    let spec = self.bits_shift_spec(cmd_name, Some(lhs))?;
                    Ok(nu_protocol::Value::int(
                        Self::bits_shift_output(cmd_name, lhs, spec)?,
                        nu_protocol::Span::unknown(),
                    ))
                })
                .collect::<Result<Vec<_>, CompileError>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(nu_protocol::Value::Binary { val, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.as_ref())
        {
            let count = self.bits_binary_shift_rotate_count(cmd_name)?;
            let output = Self::bits_binary_shift_rotate_output(cmd_name, val, count)?;
            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(input_meta) = input_meta.as_ref()
            && input_meta.list_buffer.is_some()
        {
            let spec = self.bits_shift_spec(cmd_name, None)?;
            if spec.mode == BitsShiftMode::UnsignedI64 && cmd_name == "bits shl" {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} unsigned --number-bytes 8 requires compile-time known integer input or runtime u8, u16, or u32 scalar input in eBPF; use --signed --number-bytes 8 for runtime list input"
                )));
            }
            let op = Self::bits_shift_op(cmd_name, spec.mode);
            let rhs_value = MirValue::Const(spec.count);
            if spec.mode == BitsShiftMode::SignedI64 {
                return self.lower_bits_binary_runtime_list(
                    cmd_name,
                    src_dst,
                    input_vreg,
                    result_vreg,
                    input_meta,
                    op,
                    rhs_value,
                );
            }
            return self.lower_bits_shift_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                input_meta,
                spec,
            );
        }

        self.validate_bits_integer_operand_optional_metadata(
            cmd_name,
            "pipeline input",
            input_meta.as_ref(),
            input_vreg,
        )?;
        let lhs_const = input_meta
            .as_ref()
            .and_then(Self::bits_integer_value_from_metadata);
        let lhs_value = lhs_const.map_or(MirValue::VReg(input_vreg), MirValue::Const);

        if let Some(input) = lhs_const {
            let spec = self.bits_shift_spec(cmd_name, Some(input))?;
            let output = Self::bits_shift_output(cmd_name, input, spec)?;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(output),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = Some(nu_protocol::Value::int(
                output,
                nu_protocol::Span::unknown(),
            ));
            out_meta.literal_int = Some(output);
        } else {
            let spec = self.bits_shift_spec(cmd_name, None)?;
            if spec.mode == BitsShiftMode::UnsignedI64 && cmd_name == "bits shl" {
                self.validate_bits_unsigned_i64_left_shift_runtime_scalar(
                    cmd_name,
                    input_meta.as_ref(),
                    input_vreg,
                    spec.count,
                )?;
                self.emit_bits_shift_unsigned_i64_left_value(result_vreg, lhs_value, spec.count);
            } else {
                self.emit_bits_shift_value(cmd_name, result_vreg, lhs_value, spec);
            }
            self.reset_call_result_metadata(src_dst);
            self.get_or_create_metadata(src_dst).field_type = Some(MirType::I64);
        }
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    fn emit_bits_shift_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        spec: BitsShiftSpec,
    ) {
        match spec.mode {
            BitsShiftMode::SignedI64 => {
                self.emit(MirInst::BinOp {
                    dst,
                    op: Self::bits_shift_op(cmd_name, spec.mode),
                    lhs: src,
                    rhs: MirValue::Const(spec.count),
                });
            }
            BitsShiftMode::UnsignedI64 => {
                self.emit_bits_shift_unsigned_i64_value(cmd_name, dst, src, spec.count);
            }
            BitsShiftMode::FixedWidth { mask, sign_bit, .. } => {
                let negative_block = self.func.alloc_block();
                let non_negative_block = self.func.alloc_block();
                let continuation_block = self.func.alloc_block();

                let is_negative_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: is_negative_vreg,
                    op: BinOpKind::Lt,
                    lhs: src.clone(),
                    rhs: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(is_negative_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: is_negative_vreg,
                    if_true: negative_block,
                    if_false: non_negative_block,
                });

                self.current_block = negative_block;
                self.emit_bits_shift_fixed_negative_value(
                    cmd_name,
                    dst,
                    src.clone(),
                    spec.count,
                    mask,
                    sign_bit,
                );
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = non_negative_block;
                self.emit_bits_shift_fixed_unsigned_value(cmd_name, dst, src, spec.count, mask);
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = continuation_block;
            }
            BitsShiftMode::SignedFixedWidth { mask, sign_bit, .. } => {
                self.emit_bits_shift_signed_fixed_value(
                    cmd_name, dst, src, spec.count, mask, sign_bit,
                );
            }
        }
        self.vreg_type_hints.insert(dst, MirType::I64);
    }

    fn emit_bits_shift_unsigned_i64_left_value(&mut self, dst: VReg, src: MirValue, count: i64) {
        if count == 0 {
            self.emit(MirInst::Copy { dst, src });
        } else {
            self.emit(MirInst::BinOp {
                dst,
                op: BinOpKind::Shl,
                lhs: src,
                rhs: MirValue::Const(count),
            });
        }
        self.vreg_type_hints.insert(dst, MirType::I64);
    }

    fn emit_bits_shift_unsigned_i64_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        shift_count: i64,
    ) {
        match cmd_name {
            "bits shl" => {
                unreachable!("runtime unsigned 8-byte left shifts can exceed i64::MAX")
            }
            "bits shr" => {
                if shift_count == 0 {
                    self.emit(MirInst::Copy { dst, src });
                    return;
                }

                let negative_block = self.func.alloc_block();
                let non_negative_block = self.func.alloc_block();
                let continuation_block = self.func.alloc_block();

                let is_negative_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: is_negative_vreg,
                    op: BinOpKind::Lt,
                    lhs: src.clone(),
                    rhs: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(is_negative_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: is_negative_vreg,
                    if_true: negative_block,
                    if_false: non_negative_block,
                });

                self.current_block = negative_block;
                self.emit(MirInst::BinOp {
                    dst,
                    op: BinOpKind::ArShr,
                    lhs: src.clone(),
                    rhs: MirValue::Const(shift_count),
                });
                self.vreg_type_hints.insert(dst, MirType::I64);
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = non_negative_block;
                self.emit(MirInst::BinOp {
                    dst,
                    op: BinOpKind::Shr,
                    lhs: src,
                    rhs: MirValue::Const(shift_count),
                });
                self.vreg_type_hints.insert(dst, MirType::I64);
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = continuation_block;
            }
            _ => unreachable!("validated bits shift command"),
        }
    }

    fn emit_bits_shift_fixed_unsigned_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        shift_count: i64,
        mask: i64,
    ) {
        let truncated_vreg = self.func.alloc_vreg();
        self.emit_mask_i64(truncated_vreg, src, mask);

        match cmd_name {
            "bits shl" => {
                if shift_count == 0 {
                    self.emit(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(truncated_vreg),
                    });
                } else {
                    let shifted_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: shifted_vreg,
                        op: BinOpKind::Shl,
                        lhs: MirValue::VReg(truncated_vreg),
                        rhs: MirValue::Const(shift_count),
                    });
                    self.vreg_type_hints.insert(shifted_vreg, MirType::I64);
                    self.emit_mask_i64(dst, MirValue::VReg(shifted_vreg), mask);
                }
            }
            "bits shr" => {
                if shift_count == 0 {
                    self.emit(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(truncated_vreg),
                    });
                } else {
                    self.emit(MirInst::BinOp {
                        dst,
                        op: BinOpKind::Shr,
                        lhs: MirValue::VReg(truncated_vreg),
                        rhs: MirValue::Const(shift_count),
                    });
                    self.vreg_type_hints.insert(dst, MirType::I64);
                }
            }
            _ => unreachable!("validated bits shift command"),
        }
    }

    fn emit_bits_shift_fixed_negative_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        shift_count: i64,
        mask: i64,
        sign_bit: i64,
    ) {
        let truncated_vreg = self.func.alloc_vreg();
        self.emit_mask_i64(truncated_vreg, src, mask);

        match cmd_name {
            "bits shl" => {
                let shifted_value = if shift_count == 0 {
                    MirValue::VReg(truncated_vreg)
                } else {
                    let shifted_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: shifted_vreg,
                        op: BinOpKind::Shl,
                        lhs: MirValue::VReg(truncated_vreg),
                        rhs: MirValue::Const(shift_count),
                    });
                    self.vreg_type_hints.insert(shifted_vreg, MirType::I64);
                    MirValue::VReg(shifted_vreg)
                };
                let masked_vreg = self.func.alloc_vreg();
                self.emit_mask_i64(masked_vreg, shifted_value, mask);
                self.emit_sign_extend_i64(dst, MirValue::VReg(masked_vreg), sign_bit);
            }
            "bits shr" => {
                let signed_vreg = self.func.alloc_vreg();
                self.emit_sign_extend_i64(signed_vreg, MirValue::VReg(truncated_vreg), sign_bit);
                if shift_count == 0 {
                    self.emit(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(signed_vreg),
                    });
                } else {
                    self.emit(MirInst::BinOp {
                        dst,
                        op: BinOpKind::ArShr,
                        lhs: MirValue::VReg(signed_vreg),
                        rhs: MirValue::Const(shift_count),
                    });
                    self.vreg_type_hints.insert(dst, MirType::I64);
                }
            }
            _ => unreachable!("validated bits shift command"),
        }
    }

    fn emit_bits_shift_signed_fixed_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        shift_count: i64,
        mask: i64,
        sign_bit: i64,
    ) {
        let truncated_vreg = self.func.alloc_vreg();
        self.emit_mask_i64(truncated_vreg, src, mask);

        let signed_vreg = self.func.alloc_vreg();
        self.emit_sign_extend_i64(signed_vreg, MirValue::VReg(truncated_vreg), sign_bit);

        match cmd_name {
            "bits shl" => {
                let shifted_value = if shift_count == 0 {
                    MirValue::VReg(signed_vreg)
                } else {
                    let shifted_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: shifted_vreg,
                        op: BinOpKind::Shl,
                        lhs: MirValue::VReg(signed_vreg),
                        rhs: MirValue::Const(shift_count),
                    });
                    self.vreg_type_hints.insert(shifted_vreg, MirType::I64);
                    MirValue::VReg(shifted_vreg)
                };
                let masked_vreg = self.func.alloc_vreg();
                self.emit_mask_i64(masked_vreg, shifted_value, mask);
                self.emit_sign_extend_i64(dst, MirValue::VReg(masked_vreg), sign_bit);
            }
            "bits shr" => {
                if shift_count == 0 {
                    self.emit(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(signed_vreg),
                    });
                } else {
                    self.emit(MirInst::BinOp {
                        dst,
                        op: BinOpKind::ArShr,
                        lhs: MirValue::VReg(signed_vreg),
                        rhs: MirValue::Const(shift_count),
                    });
                    self.vreg_type_hints.insert(dst, MirType::I64);
                }
            }
            _ => unreachable!("validated bits shift command"),
        }
    }

    fn emit_mask_i64(&mut self, dst: VReg, src: MirValue, mask: i64) {
        let mask_value = self.large_const_operand(&MirType::I64, mask);
        self.emit(MirInst::BinOp {
            dst,
            op: BinOpKind::And,
            lhs: src,
            rhs: mask_value,
        });
        self.vreg_type_hints.insert(dst, MirType::I64);
    }

    fn emit_sign_extend_i64(&mut self, dst: VReg, src: MirValue, sign_bit: i64) {
        let xor_vreg = self.func.alloc_vreg();
        let sign_bit_value = self.large_const_operand(&MirType::I64, sign_bit);
        self.emit(MirInst::BinOp {
            dst: xor_vreg,
            op: BinOpKind::Xor,
            lhs: src,
            rhs: sign_bit_value.clone(),
        });
        self.vreg_type_hints.insert(xor_vreg, MirType::I64);
        self.emit(MirInst::BinOp {
            dst,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(xor_vreg),
            rhs: sign_bit_value,
        });
        self.vreg_type_hints.insert(dst, MirType::I64);
    }

    pub(in crate::compiler::ir_to_mir) fn lower_bits_rotate(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_BITS_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned();

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            if !vals.is_empty()
                && vals
                    .iter()
                    .all(|value| matches!(value, nu_protocol::Value::Binary { .. }))
            {
                let count = self.bits_binary_shift_rotate_count(cmd_name)?;
                let output = vals
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let nu_protocol::Value::Binary { val, .. } = value else {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires binary list items in eBPF; item {index} has type {}",
                                value.get_type()
                            )));
                        };
                        Ok(nu_protocol::Value::binary(
                            Self::bits_binary_shift_rotate_output(cmd_name, &val, count)?,
                            nu_protocol::Span::unknown(),
                        ))
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                return self.lower_bits_binary_list_output(cmd_name, src_dst, output);
            }

            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let lhs = match value {
                        nu_protocol::Value::Int { val, .. } => val,
                        other => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires integer list items in eBPF; item {index} has type {}",
                                other.get_type()
                            )));
                        }
                    };
                    let spec = self.bits_rotate_spec(cmd_name, Some(lhs))?;
                    Ok(nu_protocol::Value::int(
                        Self::bits_rotate_output(cmd_name, lhs, spec)?,
                        nu_protocol::Span::unknown(),
                    ))
                })
                .collect::<Result<Vec<_>, CompileError>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(nu_protocol::Value::Binary { val, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.as_ref())
        {
            let count = self.bits_binary_shift_rotate_count(cmd_name)?;
            let output = Self::bits_binary_shift_rotate_output(cmd_name, val, count)?;
            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(input_meta) = input_meta.as_ref()
            && input_meta.list_buffer.is_some()
        {
            let spec = self.bits_rotate_spec(cmd_name, None)?;
            if spec.mode == BitsShiftMode::UnsignedI64 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} unsigned --number-bytes 8 requires compile-time known integer input or runtime u8, u16, or u32 scalar input for safe bits rol counts in eBPF; use --signed --number-bytes 8 for runtime list input"
                )));
            }
            return self.lower_bits_rotate_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                input_meta,
                spec,
            );
        }

        self.validate_bits_integer_operand_optional_metadata(
            cmd_name,
            "pipeline input",
            input_meta.as_ref(),
            input_vreg,
        )?;
        let lhs_const = input_meta
            .as_ref()
            .and_then(Self::bits_integer_value_from_metadata);
        let lhs_value = lhs_const.map_or(MirValue::VReg(input_vreg), MirValue::Const);

        if let Some(input) = lhs_const {
            let spec = self.bits_rotate_spec(cmd_name, Some(input))?;
            let output = Self::bits_rotate_output(cmd_name, input, spec)?;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(output),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = Some(nu_protocol::Value::int(
                output,
                nu_protocol::Span::unknown(),
            ));
            out_meta.literal_int = Some(output);
        } else {
            let spec = self.bits_rotate_spec(cmd_name, None)?;
            if spec.mode == BitsShiftMode::UnsignedI64 {
                if cmd_name != "bits rol" {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} unsigned --number-bytes 8 requires compile-time known integer input in eBPF; use --signed --number-bytes 8 for runtime 64-bit rotates"
                    )));
                }
                self.validate_bits_unsigned_i64_left_rotate_runtime_scalar(
                    cmd_name,
                    input_meta.as_ref(),
                    input_vreg,
                    spec.count,
                )?;
                self.emit_bits_rotate_unsigned_i64_left_value(result_vreg, lhs_value, spec.count);
            } else {
                self.emit_bits_rotate_value(cmd_name, result_vreg, lhs_value, spec);
            }
            self.reset_call_result_metadata(src_dst);
            self.get_or_create_metadata(src_dst).field_type = Some(MirType::I64);
        }
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    fn lower_bits_rotate_runtime_list(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        input_vreg: VReg,
        result_vreg: VReg,
        input_meta: &RegMetadata,
        spec: BitsRotateSpec,
    ) -> Result<(), CompileError> {
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires stack-backed integer-list input in eBPF"
            )));
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

        if max_len > 0 {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for index in 0..max_len {
                let transform_block = self.func.alloc_block();
                let next_block = if index + 1 == max_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: transform_block,
                    if_false: next_block,
                });

                self.current_block = transform_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);

                let output_vreg = self.func.alloc_vreg();
                self.emit_bits_rotate_value(cmd_name, output_vreg, MirValue::VReg(item_vreg), spec);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: output_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        let known_len = Self::numeric_list_known_len(input_meta).map(|len| len.min(max_len));
        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        Ok(())
    }

    fn emit_bits_rotate_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        spec: BitsRotateSpec,
    ) {
        match spec.mode {
            BitsShiftMode::SignedI64 => {
                self.emit_bits_rotate_signed_i64_value(cmd_name, dst, src, spec.count);
            }
            BitsShiftMode::UnsignedI64 => {
                unreachable!("unsigned 8-byte rotates require compile-time known integer input")
            }
            BitsShiftMode::FixedWidth {
                bits,
                mask,
                sign_bit,
            } => {
                let negative_block = self.func.alloc_block();
                let non_negative_block = self.func.alloc_block();
                let continuation_block = self.func.alloc_block();

                let is_negative_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: is_negative_vreg,
                    op: BinOpKind::Lt,
                    lhs: src.clone(),
                    rhs: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(is_negative_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: is_negative_vreg,
                    if_true: negative_block,
                    if_false: non_negative_block,
                });

                self.current_block = negative_block;
                let rotated_vreg = self.func.alloc_vreg();
                self.emit_bits_rotate_fixed_unsigned_value(
                    cmd_name,
                    rotated_vreg,
                    src.clone(),
                    spec.count,
                    bits,
                    mask,
                );
                self.emit_sign_extend_i64(dst, MirValue::VReg(rotated_vreg), sign_bit);
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = non_negative_block;
                self.emit_bits_rotate_fixed_unsigned_value(
                    cmd_name, dst, src, spec.count, bits, mask,
                );
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = continuation_block;
            }
            BitsShiftMode::SignedFixedWidth {
                bits,
                mask,
                sign_bit,
            } => {
                let rotated_vreg = self.func.alloc_vreg();
                self.emit_bits_rotate_fixed_unsigned_value(
                    cmd_name,
                    rotated_vreg,
                    src,
                    spec.count,
                    bits,
                    mask,
                );
                self.emit_sign_extend_i64(dst, MirValue::VReg(rotated_vreg), sign_bit);
            }
        }
        self.vreg_type_hints.insert(dst, MirType::I64);
    }

    fn emit_bits_rotate_unsigned_i64_left_value(&mut self, dst: VReg, src: MirValue, count: i64) {
        if count == 0 || count == 64 {
            self.emit(MirInst::Copy { dst, src });
        } else {
            self.emit(MirInst::BinOp {
                dst,
                op: BinOpKind::Shl,
                lhs: src,
                rhs: MirValue::Const(count),
            });
        }
        self.vreg_type_hints.insert(dst, MirType::I64);
    }

    fn emit_bits_rotate_signed_i64_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        rotate_count: i64,
    ) {
        if rotate_count == 0 || rotate_count == 64 {
            self.emit(MirInst::Copy { dst, src });
            return;
        }

        let lhs_vreg = self.func.alloc_vreg();
        let rhs_vreg = self.func.alloc_vreg();
        let inverse_count = 64 - rotate_count;

        let (lhs_op, lhs_count, rhs_op, rhs_count) = match cmd_name {
            "bits rol" => (BinOpKind::Shl, rotate_count, BinOpKind::Shr, inverse_count),
            "bits ror" => (BinOpKind::Shr, rotate_count, BinOpKind::Shl, inverse_count),
            _ => unreachable!("validated bits rotate command"),
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: lhs_op,
            lhs: src.clone(),
            rhs: MirValue::Const(lhs_count),
        });
        self.vreg_type_hints.insert(lhs_vreg, MirType::I64);
        self.emit(MirInst::BinOp {
            dst: rhs_vreg,
            op: rhs_op,
            lhs: src,
            rhs: MirValue::Const(rhs_count),
        });
        self.vreg_type_hints.insert(rhs_vreg, MirType::I64);
        self.emit(MirInst::BinOp {
            dst,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });
    }

    fn emit_bits_rotate_fixed_unsigned_value(
        &mut self,
        cmd_name: &str,
        dst: VReg,
        src: MirValue,
        rotate_count: i64,
        bits: i64,
        mask: i64,
    ) {
        let truncated_vreg = self.func.alloc_vreg();
        self.emit_mask_i64(truncated_vreg, src, mask);

        let rotate = rotate_count % bits;
        if rotate == 0 {
            self.emit(MirInst::Copy {
                dst,
                src: MirValue::VReg(truncated_vreg),
            });
            self.vreg_type_hints.insert(dst, MirType::I64);
            return;
        }

        let lhs_vreg = self.func.alloc_vreg();
        let rhs_vreg = self.func.alloc_vreg();
        let inverse_count = bits - rotate;
        let (lhs_op, lhs_count, rhs_op, rhs_count) = match cmd_name {
            "bits rol" => (BinOpKind::Shl, rotate, BinOpKind::Shr, inverse_count),
            "bits ror" => (BinOpKind::Shr, rotate, BinOpKind::Shl, inverse_count),
            _ => unreachable!("validated bits rotate command"),
        };

        self.emit(MirInst::BinOp {
            dst: lhs_vreg,
            op: lhs_op,
            lhs: MirValue::VReg(truncated_vreg),
            rhs: MirValue::Const(lhs_count),
        });
        self.vreg_type_hints.insert(lhs_vreg, MirType::I64);
        self.emit(MirInst::BinOp {
            dst: rhs_vreg,
            op: rhs_op,
            lhs: MirValue::VReg(truncated_vreg),
            rhs: MirValue::Const(rhs_count),
        });
        self.vreg_type_hints.insert(rhs_vreg, MirType::I64);

        let rotated_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: rotated_vreg,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
        });
        self.vreg_type_hints.insert(rotated_vreg, MirType::I64);
        self.emit_mask_i64(dst, MirValue::VReg(rotated_vreg), mask);
    }

    pub(in crate::compiler::ir_to_mir) fn lower_bits_not(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_BITS_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned();

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            if !vals.is_empty()
                && vals
                    .iter()
                    .all(|value| matches!(value, nu_protocol::Value::Binary { .. }))
            {
                self.validate_bits_not_binary_flags(cmd_name)?;
                let output = vals
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let nu_protocol::Value::Binary { val, .. } = value else {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires binary list items in eBPF; item {index} has type {}",
                                value.get_type()
                            )));
                        };
                        Ok(nu_protocol::Value::binary(
                            Self::bits_not_binary_bytes_output(&val),
                            nu_protocol::Span::unknown(),
                        ))
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                return self.lower_bits_binary_list_output(cmd_name, src_dst, output);
            }

            let mode = self.bits_not_mode(cmd_name)?;
            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let val = match value {
                        nu_protocol::Value::Int { val, .. } => val,
                        other => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires integer list items in eBPF; item {index} has type {}",
                                other.get_type()
                            )));
                        }
                    };
                    Ok(nu_protocol::Value::int(
                        Self::bits_not_output(cmd_name, val, mode)?,
                        nu_protocol::Span::unknown(),
                    ))
                })
                .collect::<Result<Vec<_>, CompileError>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(nu_protocol::Value::Binary { val, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.as_ref())
        {
            self.validate_bits_not_binary_flags(cmd_name)?;
            let output = Self::bits_not_binary_bytes_output(val);
            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        let mode = self.bits_not_mode(cmd_name)?;
        if let Some(input_meta) = input_meta.as_ref()
            && let Some((_input_slot, max_len)) = input_meta.list_buffer
        {
            if mode == BitsNotMode::Auto {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} default auto-width integer mode requires compile-time known input in eBPF; use --number-bytes 1, 2, 4, or 8 for runtime input"
                )));
            }
            let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

            if max_len > 0 {
                let len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: len_vreg,
                    list: input_vreg,
                });
                self.vreg_type_hints.insert(len_vreg, MirType::U64);

                let continuation_block = self.func.alloc_block();
                for index in 0..max_len {
                    let transform_block = self.func.alloc_block();
                    let next_block = if index + 1 == max_len {
                        continuation_block
                    } else {
                        self.func.alloc_block()
                    };

                    let in_bounds_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: in_bounds_vreg,
                        op: BinOpKind::Lt,
                        lhs: MirValue::Const(index as i64),
                        rhs: MirValue::VReg(len_vreg),
                    });
                    self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                    self.terminate(MirInst::Branch {
                        cond: in_bounds_vreg,
                        if_true: transform_block,
                        if_false: next_block,
                    });

                    self.current_block = transform_block;
                    let item_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListGet {
                        dst: item_vreg,
                        list: input_vreg,
                        idx: MirValue::Const(index as i64),
                    });
                    self.vreg_type_hints.insert(item_vreg, MirType::I64);

                    let output_vreg = self.func.alloc_vreg();
                    self.emit_bits_not_value(output_vreg, MirValue::VReg(item_vreg), mode);
                    self.vreg_type_hints.insert(output_vreg, MirType::I64);
                    self.emit(MirInst::ListPush {
                        list: result_vreg,
                        item: output_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });

                    self.current_block = next_block;
                }
            }

            let known_len = Self::numeric_list_known_len(input_meta).map(|len| len.min(max_len));
            self.install_stack_numeric_list_result_metadata(
                src_dst, out_slot, out_ty, max_len, known_len,
            );
            return Ok(());
        }

        self.validate_bits_integer_operand_optional_metadata(
            cmd_name,
            "pipeline input",
            input_meta.as_ref(),
            input_vreg,
        )?;
        if let Some(input) = input_meta
            .as_ref()
            .and_then(Self::bits_integer_value_from_metadata)
        {
            let output = Self::bits_not_output(cmd_name, input, mode)?;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(output),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = Some(nu_protocol::Value::int(
                output,
                nu_protocol::Span::unknown(),
            ));
            out_meta.literal_int = Some(output);
        } else {
            if mode == BitsNotMode::Auto {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} default auto-width integer mode requires compile-time known input in eBPF; use --number-bytes 1, 2, 4, or 8 for runtime input"
                )));
            }
            self.emit_bits_not_value(result_vreg, MirValue::VReg(input_vreg), mode);
            self.reset_call_result_metadata(src_dst);
            self.get_or_create_metadata(src_dst).field_type = Some(MirType::I64);
        }
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    fn emit_bits_not_value(&mut self, dst: VReg, src: MirValue, mode: BitsNotMode) {
        debug_assert_ne!(mode, BitsNotMode::Auto);
        self.emit(MirInst::UnaryOp {
            dst,
            op: UnaryOpKind::BitNot,
            src: src.clone(),
        });
        if let BitsNotMode::Masked { mask } = mode {
            let continuation_block = self.func.alloc_block();
            let non_negative_block = self.func.alloc_block();

            let is_negative_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: is_negative_vreg,
                op: BinOpKind::Lt,
                lhs: src,
                rhs: MirValue::Const(0),
            });
            self.vreg_type_hints.insert(is_negative_vreg, MirType::Bool);
            self.terminate(MirInst::Branch {
                cond: is_negative_vreg,
                if_true: continuation_block,
                if_false: non_negative_block,
            });

            self.current_block = non_negative_block;
            self.emit_mask_i64(dst, MirValue::VReg(dst), mask);
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = continuation_block;
        }
    }

    fn lower_bits_binary_runtime_list(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        input_vreg: VReg,
        result_vreg: VReg,
        input_meta: &RegMetadata,
        op: BinOpKind,
        rhs_value: MirValue,
    ) -> Result<(), CompileError> {
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed integer list in eBPF"
            )));
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

        if max_len > 0 {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for index in 0..max_len {
                let transform_block = self.func.alloc_block();
                let next_block = if index + 1 == max_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: transform_block,
                    if_false: next_block,
                });

                self.current_block = transform_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);

                let output_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: output_vreg,
                    op,
                    lhs: MirValue::VReg(item_vreg),
                    rhs: rhs_value.clone(),
                });
                self.vreg_type_hints.insert(output_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: output_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        let known_len = Self::numeric_list_known_len(input_meta).map(|len| len.min(max_len));
        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        Ok(())
    }

    fn lower_bits_shift_runtime_list(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        input_vreg: VReg,
        result_vreg: VReg,
        input_meta: &RegMetadata,
        spec: BitsShiftSpec,
    ) -> Result<(), CompileError> {
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed integer list in eBPF"
            )));
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

        if max_len > 0 {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for index in 0..max_len {
                let transform_block = self.func.alloc_block();
                let next_block = if index + 1 == max_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: transform_block,
                    if_false: next_block,
                });

                self.current_block = transform_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);

                let output_vreg = self.func.alloc_vreg();
                self.emit_bits_shift_value(cmd_name, output_vreg, MirValue::VReg(item_vreg), spec);
                self.vreg_type_hints.insert(output_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: output_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        let known_len = Self::numeric_list_known_len(input_meta).map(|len| len.min(max_len));
        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        Ok(())
    }
}
