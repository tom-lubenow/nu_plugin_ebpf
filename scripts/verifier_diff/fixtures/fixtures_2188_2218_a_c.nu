const VERIFIER_DIFF_FIXTURES_2188_2218_A_C = [
    {
        name: "core-map-put-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-put reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put requires a value from pipeline input"
    }
    {
        name: "core-map-push-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-push reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-push recent --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-push requires a value from pipeline input"
    }
    {
        name: "core-global-set-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-set requires a value from pipeline input"
    }
    {
        name: "core-global-define-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-define state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define requires a compile-time constant value from pipeline input"
    }
]
