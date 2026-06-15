const VERIFIER_DIFF_FIXTURES_2188_2218_A_B = [
    {
        name: "core-random-int-rejects-pipeline-input"
        category: "language-core"
        tags: [random reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | random int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-define-rejects-pipeline-input"
        category: "language-core"
        tags: [maps map-define reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-define seen --kind hash --key-type u64 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-start-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | start-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-stop-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | stop-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-timer-allows-after-prior-statement"
        category: "language-core"
        tags: [timer accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  start-timer'
            '  stop-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
