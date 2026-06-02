use super::*;
use crate::compiler::mir::{BinOpKind, UnaryOpKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitsNotMode {
    Signed,
    Auto,
    Masked { mask: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitsShiftMode {
    SignedI64,
    FixedWidth { bits: i64, mask: i64, sign_bit: i64 },
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

    fn bits_shift_op(cmd_name: &str, mode: BitsShiftMode) -> BinOpKind {
        match cmd_name {
            "bits shl" => BinOpKind::Shl,
            "bits shr" => match mode {
                BitsShiftMode::SignedI64 => BinOpKind::ArShr,
                BitsShiftMode::FixedWidth { .. } => BinOpKind::Shr,
            },
            _ => unreachable!("validated bits shift command"),
        }
    }

    fn bits_shift_output(cmd_name: &str, lhs: i64, spec: BitsShiftSpec) -> i64 {
        debug_assert!(spec.count >= 0);
        let shift = spec.count as u32;
        match spec.mode {
            BitsShiftMode::SignedI64 => {
                debug_assert!(spec.count < 64);
                match cmd_name {
                    "bits shl" => lhs.wrapping_shl(shift),
                    "bits shr" => lhs >> shift,
                    _ => unreachable!("validated bits shift command"),
                }
            }
            BitsShiftMode::FixedWidth { mask, sign_bit, .. } => {
                let truncated = lhs & mask;
                if lhs < 0 {
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
                }
            }
        }
    }

    fn sign_extend_width(value: i64, sign_bit: i64) -> i64 {
        (value ^ sign_bit) - sign_bit
    }

    fn bits_rotate_output(cmd_name: &str, lhs: i64, spec: BitsRotateSpec) -> i64 {
        debug_assert!(spec.count >= 0);
        match spec.mode {
            BitsShiftMode::SignedI64 => {
                debug_assert!(spec.count <= 64);
                let rotate = spec.count as u32;
                match cmd_name {
                    "bits rol" => lhs.rotate_left(rotate),
                    "bits ror" => lhs.rotate_right(rotate),
                    _ => unreachable!("validated bits rotate command"),
                }
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
                    Self::sign_extend_width(rotated, sign_bit)
                } else {
                    rotated
                }
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
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} masked integer mode supports --number-bytes 1, 2, or 4 in eBPF; got {number_bytes}"
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
            BitsNotMode::Masked { mask } => Ok((!input) & mask),
        }
    }

    fn bits_not_auto_output(cmd_name: &str, input: i64) -> Result<i64, CompileError> {
        if input < 0 {
            return Ok(!input);
        }

        let mask = match input {
            0..=0xff => 0xff,
            0x100..=0xffff => 0xffff,
            0x1_0000..=0xffff_ffff => 0xffff_ffff,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} default auto-width integer mode supports non-negative values up to u32::MAX in eBPF; use --number-bytes 1, 2, or 4 for wider truncation"
                )));
            }
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

    fn bits_shift_spec(&self, cmd_name: &str) -> Result<BitsShiftSpec, CompileError> {
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

        let Some(number_bytes_reg) = number_bytes_reg else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} default auto-width shifts are not supported in eBPF; use --number-bytes 1, 2, or 4, or --signed --number-bytes 8"
            )));
        };
        let number_bytes_meta = self.get_metadata(number_bytes_reg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires compile-time --number-bytes in eBPF"
            ))
        })?;
        let Some(number_bytes) = Self::bits_integer_value_from_metadata(number_bytes_meta) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires compile-time --number-bytes in eBPF"
            )));
        };

        let mode = if signed {
            if number_bytes != 8 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} --signed currently requires --number-bytes 8 in eBPF; got {number_bytes}"
                )));
            }
            BitsShiftMode::SignedI64
        } else {
            match number_bytes {
                1 => BitsShiftMode::FixedWidth {
                    bits: 8,
                    mask: 0xff,
                    sign_bit: 0x80,
                },
                2 => BitsShiftMode::FixedWidth {
                    bits: 16,
                    mask: 0xffff,
                    sign_bit: 0x8000,
                },
                4 => BitsShiftMode::FixedWidth {
                    bits: 32,
                    mask: 0xffff_ffff,
                    sign_bit: 0x8000_0000,
                },
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} explicit-width integer mode supports --number-bytes 1, 2, or 4 in eBPF; got {number_bytes}"
                    )));
                }
            }
        };

        if signed && number_bytes != 8 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} --signed currently requires --number-bytes 8 in eBPF; got {number_bytes}"
            )));
        }

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
            BitsShiftMode::SignedI64 => 63,
            BitsShiftMode::FixedWidth { bits, .. } => bits - 1,
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

    fn bits_rotate_spec(&self, cmd_name: &str) -> Result<BitsRotateSpec, CompileError> {
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

        let Some(number_bytes_reg) = number_bytes_reg else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} default auto-width rotates are not supported in eBPF; use --number-bytes 1, 2, or 4, or --signed --number-bytes 8"
            )));
        };
        let number_bytes_meta = self.get_metadata(number_bytes_reg).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires compile-time --number-bytes in eBPF"
            ))
        })?;
        let Some(number_bytes) = Self::bits_integer_value_from_metadata(number_bytes_meta) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires compile-time --number-bytes in eBPF"
            )));
        };
        let mode = if signed {
            if number_bytes != 8 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} --signed currently requires --number-bytes 8 in eBPF; got {number_bytes}"
                )));
            }
            BitsShiftMode::SignedI64
        } else {
            match number_bytes {
                1 => BitsShiftMode::FixedWidth {
                    bits: 8,
                    mask: 0xff,
                    sign_bit: 0x80,
                },
                2 => BitsShiftMode::FixedWidth {
                    bits: 16,
                    mask: 0xffff,
                    sign_bit: 0x8000,
                },
                4 => BitsShiftMode::FixedWidth {
                    bits: 32,
                    mask: 0xffff_ffff,
                    sign_bit: 0x8000_0000,
                },
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} explicit-width integer mode supports --number-bytes 1, 2, or 4 in eBPF; got {number_bytes}"
                    )));
                }
            }
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
            BitsShiftMode::SignedI64 => 64,
            BitsShiftMode::FixedWidth { bits, .. } => bits,
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
        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer, binary, integer-list, or binary-list input in eBPF"
            ))
        })?;

        let (rhs_vreg, rhs_reg) = self.positional_args[0];
        let rhs_meta = self.get_metadata(rhs_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer or binary target argument in eBPF"
            ))
        })?;
        let rhs_const = Self::bits_integer_value_from_metadata(&rhs_meta);
        let rhs_binary_const = Self::bits_binary_value_from_metadata(&rhs_meta);
        let op = Self::bits_binary_op(cmd_name);

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
            if !vals.is_empty()
                && vals
                    .iter()
                    .all(|value| matches!(value, nu_protocol::Value::Binary { .. }))
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
                let output_len = output
                    .first()
                    .and_then(|value| match value {
                        nu_protocol::Value::Binary { val, .. } => Some(val.len()),
                        _ => None,
                    })
                    .unwrap_or(0);
                let equal_non_empty_output = output_len > 0
                    && output.iter().all(|value| match value {
                        nu_protocol::Value::Binary { val, .. } => val.len() == output_len,
                        _ => false,
                    });
                if !equal_non_empty_output {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} binary list output requires non-empty equal-length binary items in eBPF"
                    )));
                }

                self.reset_call_result_metadata(src_dst);
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
                )?;
                return Ok(());
            }

            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            self.validate_bits_integer_operand(cmd_name, "target argument", &rhs_meta, rhs_vreg)?;
            let Some(rhs) = rhs_const else {
                if input_meta.list_buffer.is_some() {
                    // A numeric constant list is also available as a stack-backed
                    // list, so runtime list lowering below can reuse the RHS vreg.
                    return self.lower_bits_binary_runtime_list(
                        cmd_name,
                        src_dst,
                        input_vreg,
                        result_vreg,
                        &input_meta,
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

        if input_meta.list_buffer.is_some() {
            self.validate_bits_integer_operand(cmd_name, "target argument", &rhs_meta, rhs_vreg)?;
            return self.lower_bits_binary_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                &input_meta,
                op,
                rhs_const.map_or(MirValue::VReg(rhs_vreg), MirValue::Const),
            );
        }

        if let Some(nu_protocol::Value::Binary { val, .. }) = input_meta.constant_value.as_ref() {
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

        self.validate_bits_integer_operand(cmd_name, "target argument", &rhs_meta, rhs_vreg)?;
        self.validate_bits_integer_operand(cmd_name, "pipeline input", &input_meta, input_vreg)?;
        let rhs_value = rhs_const.map_or(MirValue::VReg(rhs_vreg), MirValue::Const);
        let lhs_value = Self::bits_integer_value_from_metadata(&input_meta)
            .map_or(MirValue::VReg(input_vreg), MirValue::Const);
        let constant_output = match (
            Self::bits_integer_value_from_metadata(&input_meta),
            rhs_const,
        ) {
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

        let spec = self.bits_shift_spec(cmd_name)?;
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
                "{cmd_name} requires integer or integer-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer or integer-list input in eBPF"
            ))
        })?;

        let op = Self::bits_shift_op(cmd_name, spec.mode);
        let rhs_value = MirValue::Const(spec.count);

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
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
                    Ok(nu_protocol::Value::int(
                        Self::bits_shift_output(cmd_name, lhs, spec),
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

        if input_meta.list_buffer.is_some() {
            if spec.mode == BitsShiftMode::SignedI64 {
                return self.lower_bits_binary_runtime_list(
                    cmd_name,
                    src_dst,
                    input_vreg,
                    result_vreg,
                    &input_meta,
                    op,
                    rhs_value,
                );
            }
            return self.lower_bits_shift_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                &input_meta,
                spec,
            );
        }

        self.validate_bits_integer_operand(cmd_name, "pipeline input", &input_meta, input_vreg)?;
        let lhs_value = Self::bits_integer_value_from_metadata(&input_meta)
            .map_or(MirValue::VReg(input_vreg), MirValue::Const);

        if let Some(input) = Self::bits_integer_value_from_metadata(&input_meta) {
            let output = Self::bits_shift_output(cmd_name, input, spec);
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
            self.emit_bits_shift_value(cmd_name, result_vreg, lhs_value, spec);
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
        }
        self.vreg_type_hints.insert(dst, MirType::I64);
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

        let spec = self.bits_rotate_spec(cmd_name)?;
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
                "{cmd_name} requires integer or integer-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer or integer-list input in eBPF"
            ))
        })?;

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
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
                    Ok(nu_protocol::Value::int(
                        Self::bits_rotate_output(cmd_name, lhs, spec),
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

        if input_meta.list_buffer.is_some() {
            return self.lower_bits_rotate_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                &input_meta,
                spec,
            );
        }

        self.validate_bits_integer_operand(cmd_name, "pipeline input", &input_meta, input_vreg)?;
        let lhs_value = Self::bits_integer_value_from_metadata(&input_meta)
            .map_or(MirValue::VReg(input_vreg), MirValue::Const);

        if let Some(input) = Self::bits_integer_value_from_metadata(&input_meta) {
            let output = Self::bits_rotate_output(cmd_name, input, spec);
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
            self.emit_bits_rotate_value(cmd_name, result_vreg, lhs_value, spec);
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
        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer, binary, integer-list, or binary-list input in eBPF"
            ))
        })?;

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
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
                let output_len = output
                    .first()
                    .and_then(|value| match value {
                        nu_protocol::Value::Binary { val, .. } => Some(val.len()),
                        _ => None,
                    })
                    .unwrap_or(0);
                let equal_non_empty_output = output_len > 0
                    && output.iter().all(|value| match value {
                        nu_protocol::Value::Binary { val, .. } => val.len() == output_len,
                        _ => false,
                    });
                if !equal_non_empty_output {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} binary list output requires non-empty equal-length binary items in eBPF"
                    )));
                }

                self.reset_call_result_metadata(src_dst);
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
                )?;
                return Ok(());
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

        if let Some(nu_protocol::Value::Binary { val, .. }) = input_meta.constant_value.as_ref() {
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
        if let Some((_input_slot, max_len)) = input_meta.list_buffer {
            if mode == BitsNotMode::Auto {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} default auto-width integer mode requires compile-time known input in eBPF; use --number-bytes 1, 2, or 4 for runtime input"
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

            let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(max_len));
            self.install_stack_numeric_list_result_metadata(
                src_dst, out_slot, out_ty, max_len, known_len,
            );
            return Ok(());
        }

        self.validate_bits_integer_operand(cmd_name, "pipeline input", &input_meta, input_vreg)?;
        if let Some(input) = Self::bits_integer_value_from_metadata(&input_meta) {
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
                    "{cmd_name} default auto-width integer mode requires compile-time known input in eBPF; use --number-bytes 1, 2, or 4 for runtime input"
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
            src,
        });
        if let BitsNotMode::Masked { mask } = mode {
            let mask_value = self.large_const_operand(&MirType::I64, mask);
            self.emit(MirInst::BinOp {
                dst,
                op: BinOpKind::And,
                lhs: MirValue::VReg(dst),
                rhs: mask_value,
            });
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
