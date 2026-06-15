const VERIFIER_DIFF_FIXTURES_2797_2806 = [
    {
        name: "core-operator-string-equality-accepts-two-runtime-strings"
        category: "language-core"
        tags: [operators string-equality accept runtime]
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
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-operator-starts-with-accepts-runtime-prefix"
        category: "language-core"
        tags: [operators starts-with accept runtime]
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
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-operator-ends-with-accepts-runtime-suffix"
        category: "language-core"
        tags: [operators ends-with accept runtime]
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
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-operator-in-accepts-runtime-string-needle"
        category: "language-core"
        tags: [operators in accept runtime]
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
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "core-operator-has-accepts-runtime-string-needle"
        category: "language-core"
        tags: [operators has accept runtime]
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
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
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
