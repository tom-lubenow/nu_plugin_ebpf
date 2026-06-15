const VERIFIER_DIFF_FIXTURES_0188_0218_B = [
    {
        name: "syscall-helper-context"
        category: "tracing"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  helper-call "bpf_sys_close" 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-context"
        category: "tracing"
        tags: [freplace context]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-rejects-context-field"
        category: "context-policy"
        tags: [syscall context reject]
        target: "syscall:demo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on syscall programs"
    }
    {
        name: "freplace-rejects-arg-context"
        category: "context-policy"
        tags: [freplace context reject]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.arg0 is only available on contexts with argument access"
    }
]
