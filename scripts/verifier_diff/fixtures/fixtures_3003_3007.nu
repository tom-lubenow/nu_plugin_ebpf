const VERIFIER_DIFF_FIXTURES_3003_3007 = [
    {
        name: "kprobe-context-arg-name-rejects-non-btf-context"
        category: "context"
        tags: [context kprobe arg btf diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.arg.foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg.<name> is only available on kernel-BTF-backed contexts"
    }
    {
        name: "kprobe-context-arg-index-requires-named-btf-parameter"
        category: "context"
        tags: [context kprobe arg btf diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.arg.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg.<name> requires a named BTF parameter"
    }
    {
        name: "kprobe-context-task-pt-regs-rejects-missing-register"
        category: "context"
        tags: [context kprobe task pt-regs diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'task.pt_regs' requires a pt_regs register after ctx.task.pt_regs, e.g. ctx.task.pt_regs.arg0 or ctx.task.pt_regs.retval"
    }
    {
        name: "kprobe-context-task-pt-regs-rejects-unsupported-register"
        category: "context"
        tags: [context kprobe task pt-regs diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs.foo'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'task.pt_regs.foo' has unsupported pt_regs register 'foo'; expected arg0..arg5 or retval"
    }
    {
        name: "kprobe-context-task-pt-regs-index-requires-register-name"
        category: "context"
        tags: [context kprobe task pt-regs diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'task.pt_regs.0' requires a pt_regs register after ctx.task.pt_regs, e.g. ctx.task.pt_regs.arg0 or ctx.task.pt_regs.retval"
    }
]
