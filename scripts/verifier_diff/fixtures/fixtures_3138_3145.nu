const VERIFIER_DIFF_FIXTURES_3138_3145 = [
    {
        name: "core-operator-starts-with-accepts-runtime-left-literal-right"
        category: "language-core"
        tags: [operators starts-with accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l starts-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-ends-with-accepts-runtime-left-literal-right"
        category: "language-core"
        tags: [operators ends-with accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l ends-with "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-in-accepts-literal-left-runtime-right"
        category: "language-core"
        tags: [operators in accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "a" in $l'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-has-accepts-runtime-left-literal-right"
        category: "language-core"
        tags: [operators has accept runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l has "a"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "core-operator-starts-with-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators starts-with diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" starts-with $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "starts-with operator requires a compile-time known string prefix in eBPF"
    }
    {
        name: "core-operator-ends-with-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators ends-with diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" ends-with $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ends-with operator requires a compile-time known string suffix in eBPF"
    }
    {
        name: "core-operator-in-rejects-runtime-left-literal-right"
        category: "language-core"
        tags: [operators in diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l in "abc"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "in operator requires a compile-time known string needle in eBPF"
    }
    {
        name: "core-operator-has-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators has diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" has $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "has operator requires a compile-time known string needle in eBPF"
    }
]
