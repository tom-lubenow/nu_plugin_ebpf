def target-uses-bpf-tracing-prog-type [target] {
    let target_text = ($target | default "")
    [
        ($target_text | str starts-with "fentry:")
        ($target_text | str starts-with "fentry.s:")
        ($target_text | str starts-with "fexit:")
        ($target_text | str starts-with "fexit.s:")
        ($target_text | str starts-with "fmod_ret:")
        ($target_text | str starts-with "fmod_ret.s:")
        ($target_text | str starts-with "tp_btf:")
    ] | any {|matches| $matches }
}

def program-kfunc-kernel-feature [name: string target] {
    if $name == "bpf_dynptr_from_skb" and (target-uses-bpf-tracing-prog-type $target) {
        return {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }

    kfunc-kernel-feature $name
}

def target-context-field-alias-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if $field == "retval" {
        if (
            ($target_text | str starts-with "kretprobe:")
            or ($target_text | str starts-with "kretprobe.multi:")
            or ($target_text | str starts-with "kretsyscall:")
            or ($target_text | str starts-with "uretprobe:")
            or ($target_text | str starts-with "uretprobe.s:")
            or ($target_text | str starts-with "uretprobe.multi:")
            or ($target_text | str starts-with "uretprobe.multi.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_PT_REGS }
        }
        if (
            ($target_text | str starts-with "fexit:")
            or ($target_text | str starts-with "fexit.s:")
            or ($target_text | str starts-with "fmod_ret:")
            or ($target_text | str starts-with "fmod_ret.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE }
        }
    }
    let socket_alias = (target-socket-context-field-alias-kernel-feature $field $target_text)
    if $socket_alias.matched {
        return $socket_alias
    }

    let cgroup_misc_alias = (target-cgroup-misc-context-field-alias-kernel-feature $field $target_text)
    if $cgroup_misc_alias.matched {
        return $cgroup_misc_alias
    }

    let iter_alias = (target-iter-context-field-alias-kernel-feature $field $target_text)
    if $iter_alias.matched {
        return $iter_alias
    }

    { matched: false, feature: null }
}
