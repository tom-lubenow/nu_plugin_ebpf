const VERIFIER_DIFF_FIXTURES_3054_3055 = [
    {
        name: "tail-call-rejects-empty-map-name"
        category: "language-surface"
        tags: [tail-call diagnostics reject maps]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  tail-call "" 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "tail-call map name must not be empty"
    }
    {
        name: "tail-call-rejects-invalid-map-name"
        category: "language-surface"
        tags: [tail-call diagnostics reject maps]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  tail-call "bad-name" 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "tail-call map name 'bad-name' must match [A-Za-z_][A-Za-z0-9_]*"
    }
]
