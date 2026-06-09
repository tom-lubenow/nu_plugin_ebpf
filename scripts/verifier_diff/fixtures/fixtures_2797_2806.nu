const VERIFIER_DIFF_FIXTURES_2797_2806 = [
    {
        name: "core-operator-string-equality-rejects-two-runtime-strings"
        category: "language-core"
        tags: [operators string-equality diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l == $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "string equality requires at least one compile-time known string operand in eBPF"
    }
    {
        name: "core-operator-starts-with-rejects-runtime-prefix"
        category: "language-core"
        tags: [operators starts-with diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l starts-with $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "starts-with operator requires a compile-time known string prefix in eBPF"
    }
    {
        name: "core-operator-ends-with-rejects-runtime-suffix"
        category: "language-core"
        tags: [operators ends-with diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l ends-with $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ends-with operator requires a compile-time known string suffix in eBPF"
    }
    {
        name: "core-operator-in-rejects-runtime-string-needle"
        category: "language-core"
        tags: [operators in diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l in $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "in operator requires a compile-time known string needle in eBPF"
    }
    {
        name: "core-operator-has-rejects-runtime-string-needle"
        category: "language-core"
        tags: [operators has diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l has $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "has operator requires a compile-time known string needle in eBPF"
    }
    {
        name: "core-operator-pow-rejects-runtime-exponent"
        category: "language-core"
        tags: [operators pow diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid ** $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Operator ** requires a compile-time known integer exponent in eBPF runtime lowering"
    }
    {
        name: "core-operator-pow-rejects-negative-exponent"
        category: "language-core"
        tags: [operators pow diagnostics reject negative]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid ** -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Operator ** requires a non-negative integer exponent in eBPF runtime lowering"
    }
    {
        name: "core-operator-floor-div-rejects-runtime-divisor"
        category: "language-core"
        tags: [operators floor-div diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid // ($ctx.pid + 1)'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Operator // requires a compile-time known positive integer divisor in eBPF runtime lowering"
    }
    {
        name: "core-operator-floor-div-rejects-zero-divisor"
        category: "language-core"
        tags: [operators floor-div diagnostics reject zero]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid // 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Operator // requires a positive integer divisor in eBPF runtime lowering"
    }
    {
        name: "core-operator-floor-div-rejects-unproven-nonnegative-left"
        category: "language-core"
        tags: [operators floor-div diagnostics reject range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let x = (0 - $ctx.pid)'
            '  $x // 2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Operator // supports runtime lowering only when the left operand is provably non-negative in eBPF"
    }
]
