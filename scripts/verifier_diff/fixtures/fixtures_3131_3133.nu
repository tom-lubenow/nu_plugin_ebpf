const VERIFIER_DIFF_FIXTURES_3131_3133 = [
    {
        name: "core-operator-string-ordering-rejects-runtime-strings"
        category: "language-core"
        tags: [operators string-ordering diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l < $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "string ordering comparisons require compile-time constant operands in eBPF"
    }
    {
        name: "core-operator-regex-match-rejects-runtime-strings"
        category: "language-core"
        tags: [operators regex diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l =~ $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "regex comparisons require compile-time constant string operands in eBPF"
    }
    {
        name: "core-operator-regex-not-match-rejects-runtime-strings"
        category: "language-core"
        tags: [operators regex not-regex diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:8 left'
            '  global-define --type string:8 right'
            '  let l = (global-get left)'
            '  let r = (global-get right)'
            '  $l !~ $r'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "regex comparisons require compile-time constant string operands in eBPF"
    }
]
