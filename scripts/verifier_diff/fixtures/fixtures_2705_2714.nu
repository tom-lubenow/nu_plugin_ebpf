const VERIFIER_DIFF_FIXTURES_2705_2714 = [
    {
        name: "core-char-rejects-list-output"
        category: "language-core"
        tags: [string char diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --list'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char --list produces a table and is not supported in eBPF"
    }
    {
        name: "core-char-rejects-conflicting-codepoint-flags"
        category: "language-core"
        tags: [string char diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode --integer 41'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char supports only one of --unicode or --integer in eBPF"
    }
    {
        name: "core-char-rejects-missing-arguments"
        category: "language-core"
        tags: [string char diagnostics reject arity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char requires at least one character argument in eBPF"
    }
    {
        name: "core-char-rejects-unsupported-named-character"
        category: "language-core"
        tags: [string char diagnostics reject named]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char not_a_char'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char named character 'not_a_char' is not supported in eBPF"
    }
    {
        name: "core-char-unicode-rejects-invalid-hex"
        category: "language-core"
        tags: [string char diagnostics reject unicode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode xyz'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char --unicode requires hexadecimal codepoints in eBPF, got 'xyz'"
    }
    {
        name: "core-char-unicode-rejects-non-string-codepoint"
        category: "language-core"
        tags: [string char diagnostics reject unicode type]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode 00'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char --unicode requires a compile-time string literal"
    }
    {
        name: "core-char-integer-rejects-dynamic-codepoint"
        category: "language-core"
        tags: [string char diagnostics reject integer dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --integer $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char --integer requires compile-time known integer codepoints in eBPF"
    }
    {
        name: "core-char-integer-rejects-invalid-codepoint"
        category: "language-core"
        tags: [string char diagnostics reject integer range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --integer 1114112'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char --integer codepoint U+110000 is outside the valid Unicode range in eBPF"
    }
    {
        name: "core-char-rejects-nul-output"
        category: "language-core"
        tags: [string char diagnostics reject nul]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char nul'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char output containing NUL bytes is not supported in eBPF"
    }
    {
        name: "core-char-unicode-rejects-invalid-codepoint"
        category: "language-core"
        tags: [string char diagnostics reject unicode range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode "110000"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "char --unicode codepoint U+110000 is outside the valid Unicode range in eBPF"
    }
]
