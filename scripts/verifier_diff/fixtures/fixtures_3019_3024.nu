const VERIFIER_DIFF_FIXTURES_3019_3024 = [
    {
        name: "global-get-rejects-missing-definition"
        category: "language-core"
        tags: [globals global-get diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-get missing'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-get for 'missing' requires a same-program global-define or layout-establishing global-set"
    }
    {
        name: "kfunc-call-rejects-runtime-btf-id"
        category: "language-surface"
        tags: [kfunc diagnostics reject btf runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_task_acquire" $ctx.task --btf-id $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc-call --btf-id must be a compile-time integer literal"
    }
    {
        name: "kfunc-call-rejects-negative-btf-id"
        category: "language-surface"
        tags: [kfunc diagnostics reject btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_task_acquire" $ctx.task --btf-id (-1)'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc-call --btf-id must be >= 0"
    }
    {
        name: "kfunc-call-rejects-argument-limit"
        category: "language-surface"
        tags: [kfunc diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_task_acquire" 1 2 3 4 5 6'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "BPF kfunc calls support at most 5 arguments"
    }
    {
        name: "helper-call-rejects-extra-argument"
        category: "language-surface"
        tags: [helpers diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_current_pid_tgid" 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call 'bpf_get_current_pid_tgid' expects 0..=0 helper arguments after the helper name, got 1"
    }
    {
        name: "helper-call-rejects-implicit-pipeline-with-explicit-args"
        category: "language-surface"
        tags: [helpers diagnostics reject arguments pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | helper-call "bpf_map_lookup_elem" seen'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call 'bpf_map_lookup_elem' does not prepend the piped value when explicit helper arguments are present"
    }
]
