const VERIFIER_DIFF_FIXTURES_0188_0218_A_C = [
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
]
