const VERIFIER_DIFF_FIXTURES_2358_2358 = [
    {
        name: "devmap-map-put-rejects-kind"
        category: "maps"
        tags: [maps devmap map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put devices 0 --kind devmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put --kind devmap is reserved for bpf_redirect_map"
    }
]
