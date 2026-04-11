use super::{KernelBtf, KfuncPointerRefFamily};

impl KernelBtf {
    pub(super) fn has_user_type_tag(type_tags: &[String]) -> bool {
        type_tags
            .iter()
            .any(|tag| tag == "__user" || tag.contains("__user") || tag == "address_space(1)")
    }

    pub(super) fn is_stack_object_type_name(name: &str) -> bool {
        if name.starts_with("bpf_iter_") || name == "bpf_dynptr" || name.starts_with("bpf_dynptr_")
        {
            return true;
        }

        // Broader stack-object heuristic for unknown kfuncs:
        // treat remaining bpf_* struct/union pointer args as stack-object-like
        // unless they clearly identify kernel/ref-family objects.
        let lower = name.to_ascii_lowercase();
        lower.starts_with("bpf_")
            && !lower.contains("bpf_map")
            && Self::infer_pointer_ref_family(&lower).is_none()
    }

    pub(super) fn infer_pointer_ref_family(name: &str) -> Option<KfuncPointerRefFamily> {
        let lower = name.to_ascii_lowercase();
        if lower.contains("task_struct") {
            return Some(KfuncPointerRefFamily::Task);
        }
        if lower.contains("cgroup") {
            return Some(KfuncPointerRefFamily::Cgroup);
        }
        if lower.contains("cpumask") {
            return Some(KfuncPointerRefFamily::Cpumask);
        }
        if lower == "inode" || lower.ends_with("_inode") {
            return Some(KfuncPointerRefFamily::Inode);
        }
        if lower == "file" || lower.ends_with("_file") {
            return Some(KfuncPointerRefFamily::File);
        }
        if lower.contains("sock") || lower.contains("socket") {
            return Some(KfuncPointerRefFamily::Socket);
        }
        if lower.contains("crypto_ctx") {
            return Some(KfuncPointerRefFamily::CryptoCtx);
        }
        None
    }

    pub(super) fn is_kernel_pointer_type_name(name: &str) -> bool {
        if Self::infer_pointer_ref_family(name).is_some() {
            return true;
        }
        let lower = name.to_ascii_lowercase();
        lower == "bpf_map" || lower.contains("bpf_map")
    }

    pub(super) fn is_probable_out_param_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower == "out"
            || lower.starts_with("out_")
            || lower.ends_with("_out")
            || lower.ends_with("__out")
            || lower == "dst"
            || lower.starts_with("dst_")
            || lower.ends_with("_dst")
            || lower.ends_with("__dst")
            || lower == "to"
            || lower.starts_with("to_")
            || lower.ends_with("_to")
            || lower.ends_with("__to")
            || lower == "new"
            || lower.starts_with("new_")
            || lower.ends_with("_new")
            || lower.ends_with("__new")
            || lower == "dup"
            || lower.starts_with("dup_")
            || lower.ends_with("_dup")
            || lower.ends_with("__dup")
            || lower == "err"
            || lower.ends_with("_err")
            || lower.ends_with("__err")
            || lower == "result"
            || lower.starts_with("result_")
            || lower.ends_with("_result")
            || lower.ends_with("__result")
            || lower == "retval"
            || lower.starts_with("retval_")
            || lower.ends_with("_retval")
            || lower.ends_with("__retval")
            || lower.ends_with("_uninit")
            || lower.ends_with("__uninit")
    }

    pub(super) fn is_probable_in_param_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower == "in"
            || lower.starts_with("in_")
            || lower.ends_with("_in")
            || lower.ends_with("__in")
            || lower == "src"
            || lower.starts_with("src_")
            || lower.ends_with("_src")
            || lower.ends_with("__src")
            || lower == "from"
            || lower.starts_with("from_")
            || lower.ends_with("_from")
            || lower.ends_with("__from")
            || lower == "old"
            || lower.starts_with("old_")
            || lower.ends_with("_old")
            || lower.ends_with("__old")
            || lower == "orig"
            || lower.starts_with("orig_")
            || lower.ends_with("_orig")
            || lower.ends_with("__orig")
    }

    pub(super) fn is_probable_release_kfunc_name(name: &str) -> bool {
        name.contains("_release")
            || name.contains("_destroy")
            || name.contains("_cleanup")
            || name.contains("_deinit")
            || name.contains("_fini_")
            || name.ends_with("_fini")
            || name.contains("_delete")
            || name.contains("_detach")
            || name.contains("_close")
            || name.contains("_unref")
            || name.starts_with("bpf_put_")
            || name.contains("_put_")
            || name.ends_with("_put")
            || name.contains("_drop")
            || name.contains("_free")
            || name.contains("_dec_")
            || name.ends_with("_dec")
    }

    pub(super) fn infer_release_arg_index_from_family_args(
        family_args: &[(usize, bool, bool)],
    ) -> Option<usize> {
        let select_unique = |pred: &dyn Fn(&(usize, bool, bool)) -> bool| {
            let matches: Vec<usize> = family_args
                .iter()
                .filter(|arg| pred(arg))
                .map(|(arg_idx, _, _)| *arg_idx)
                .collect();
            if matches.len() == 1 {
                matches.first().copied()
            } else {
                None
            }
        };

        select_unique(&|(_, named_out, is_const)| !*named_out && !*is_const)
            .or_else(|| select_unique(&|(_, named_out, _)| !*named_out))
            .or_else(|| select_unique(&|(_, _, is_const)| !*is_const))
            .or_else(|| select_unique(&|_| true))
    }
}
