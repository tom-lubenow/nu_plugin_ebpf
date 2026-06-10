const VERIFIER_DIFF_FIXTURES_3134_3137 = [
    {
        name: "core-operator-string-ordering-rejects-runtime-left-literal-right"
        category: "language-core"
        tags: [operators string-ordering diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l < "z"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "string ordering comparisons require compile-time constant operands in eBPF"
    }
    {
        name: "core-operator-string-ordering-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators string-ordering diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "a" < $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "string ordering comparisons require compile-time constant operands in eBPF"
    }
    {
        name: "core-operator-regex-match-rejects-runtime-left-literal-right"
        category: "language-core"
        tags: [operators regex diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  $l =~ "^a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "regex comparisons require compile-time constant string operands in eBPF"
    }
    {
        name: "core-operator-regex-match-rejects-literal-left-runtime-right"
        category: "language-core"
        tags: [operators regex diagnostics reject runtime literal]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  let l = (global-get left)'
            '  "abc" =~ $l'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "regex comparisons require compile-time constant string operands in eBPF"
    }
]
