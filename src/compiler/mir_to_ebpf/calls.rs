use super::*;
use crate::compiler::instruction::unknown_kfunc_signature_message;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compile_call_subfn(
        &mut self,
        subfn: SubfunctionId,
        args: &[VReg],
    ) -> Result<(), CompileError> {
        // BPF-to-BPF function call
        if args.len() > 5 {
            return Err(CompileError::UnsupportedInstruction(
                "BPF subfunctions support at most 5 arguments".into(),
            ));
        }

        // Emit call instruction with placeholder offset
        let call_idx = self.instructions.len();
        self.instructions.push(EbpfInsn::call_local(subfn.0 as i32));

        // Track this call for relocation
        self.subfn_calls.push((call_idx, subfn));
        Ok(())
    }

    pub(super) fn compile_call_kfunc(
        &mut self,
        kfunc: &str,
        btf_id: Option<u32>,
        args: &[VReg],
    ) -> Result<(), CompileError> {
        let sig = KfuncSignature::for_name_or_kernel_btf(kfunc).ok_or_else(|| {
            CompileError::UnsupportedInstruction(unknown_kfunc_signature_message(kfunc))
        })?;
        if args.len() < sig.min_args || args.len() > sig.max_args {
            return Err(CompileError::UnsupportedInstruction(format!(
                "kfunc '{}' expects {}..={} arguments, got {}",
                kfunc,
                sig.min_args,
                sig.max_args,
                args.len()
            )));
        }
        if args.len() > 5 {
            return Err(CompileError::UnsupportedInstruction(
                "BPF kfunc calls support at most 5 arguments".into(),
            ));
        }

        let resolved_btf_id = if let Some(btf_id) = btf_id {
            btf_id
        } else {
            KernelBtf::get()
                .resolve_kfunc_btf_id(kfunc)
                .map_err(|err| {
                    CompileError::UnsupportedInstruction(format!(
                        "failed to resolve kfunc '{}' BTF ID: {}",
                        kfunc, err
                    ))
                })?
        };

        if resolved_btf_id > i32::MAX as u32 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "kfunc '{}' BTF ID {} is out of supported range",
                kfunc, resolved_btf_id
            )));
        }

        self.instructions
            .push(EbpfInsn::call_kfunc(resolved_btf_id as i32));
        Ok(())
    }

    pub(super) fn compile_call_helper(
        &mut self,
        helper: u32,
        args: &[VReg],
    ) -> Result<(), CompileError> {
        if let Some(sig) = HelperSignature::for_id(helper) {
            if args.len() < sig.min_args || args.len() > sig.max_args {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "helper {} expects {}..={} arguments, got {}",
                    helper,
                    sig.min_args,
                    sig.max_args,
                    args.len()
                )));
            }
        } else if args.len() > 5 {
            return Err(CompileError::UnsupportedInstruction(
                "BPF helpers support at most 5 arguments".into(),
            ));
        }

        self.instructions
            .push(EbpfInsn::new(opcode::CALL, 0, 0, 0, helper as i32));
        Ok(())
    }
}
