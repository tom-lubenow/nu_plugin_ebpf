const VERIFIER_DIFF_FIXTURES_0188_0218_A = [
    {
        name: "fentry-array-element-context"
        category: "tracing"
        tags: [fentry context array]
        requires: [kernel-btf]
        target: "fentry:wake_up_new_task"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.comm.0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-sleepable-context"
        category: "tracing"
        tags: [fentry sleepable context]
        requires: [kernel-btf]
        target: "fentry.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fexit-context"
        category: "tracing"
        tags: [fexit context]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fexit-func-arg-ret-helper-calls"
        category: "tracing"
        tags: [fexit helper-call context source metadata]
        requires: [kernel-btf]
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  let arg0 = "01234567"'
            '  let retval = "01234567"'
            '  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count'
            '  (helper-call "bpf_get_func_ret" $ctx $retval) | count'
            '  (helper-call "bpf_get_func_arg_cnt" $ctx) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fentry-func-ret-helper-reject"
        category: "tracing"
        tags: [fentry helper-call context reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let retval = "01234567"'
            '  helper-call "bpf_get_func_ret" $ctx $retval'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_func_ret' is only valid in fexit and fmod_ret programs"
    }
    {
        name: "fentry-missing-target-help-reject"
        category: "tracing"
        tags: [fentry context diagnostic reject]
        requires: [kernel-btf]
        target: "fentry:nu_plugin_ebpf_missing_function_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "target signature"
    }
    {
        name: "fexit-sleepable-context"
        category: "tracing"
        tags: [fexit sleepable context]
        requires: [kernel-btf]
        target: "fexit.s:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg0 + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-context"
        category: "tracing"
        tags: [fmod-ret context]
        requires: [kernel-btf]
        target: "fmod_ret:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "fmod-ret-sleepable-context"
        category: "tracing"
        tags: [fmod-ret sleepable context]
        requires: [kernel-btf]
        target: "fmod_ret.s:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-context"
        category: "tracing"
        tags: [lsm context]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-sleepable-context"
        category: "tracing"
        tags: [lsm sleepable context]
        requires: [kernel-btf]
        target: "lsm.s:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-bound-arg-context"
        category: "tracing"
        tags: [lsm context alias]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  ($file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-missing-target-help-reject"
        category: "tracing"
        tags: [lsm context diagnostic reject]
        requires: [kernel-btf]
        target: "lsm:nu_plugin_ebpf_missing_hook_for_help"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "LSM hook name"
    }
    {
        name: "lsm-cgroup-context"
        category: "tracing"
        tags: [lsm-cgroup context]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg2 + $ctx.arg_count + $ctx.pid) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg_count is only available on BTF-backed tracing contexts with bpf_get_func_arg_cnt support"
    }
    {
        name: "lsm-cgroup-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lsm-cgroup-live-target-named-arg-context"
        category: "tracing"
        tags: [lsm-cgroup context named-arg cgroup-path source metadata]
        requires: [kernel-btf]
        target: "lsm_cgroup:/sys/fs/cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg.address.sa_family + $ctx.arg.addrlen) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
