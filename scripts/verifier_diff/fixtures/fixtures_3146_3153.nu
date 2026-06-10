const VERIFIER_DIFF_FIXTURES_3146_3153 = [
    {
        name: "core-operator-not-starts-with-accepts-runtime-left-literal-right"
        category: "language-core"
        tags: [operators not-starts-with accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l not-starts-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-not-ends-with-accepts-runtime-left-literal-right"
        category: "language-core"
        tags: [operators not-ends-with accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l not-ends-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-not-in-accepts-literal-left-runtime-right"
        category: "language-core"
        tags: [operators not-in accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "a" not-in $l'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-not-has-accepts-runtime-left-literal-right"
        category: "language-core"
        tags: [operators not-has accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l not-has "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-not-starts-with-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators not-starts-with diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" not-starts-with $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "starts-with operator requires a compile-time known string prefix in eBPF"
    }
    {
        name: "core-operator-not-ends-with-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators not-ends-with diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" not-ends-with $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ends-with operator requires a compile-time known string suffix in eBPF"
    }
    {
        name: "core-operator-not-in-rejects-runtime-left-literal-right"
        category: "language-core"
        tags: [operators not-in diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l not-in "abc"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "in operator requires a compile-time known string needle in eBPF"
    }
    {
        name: "core-operator-not-has-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators not-has diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" not-has $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "has operator requires a compile-time known string needle in eBPF"
    }
]
