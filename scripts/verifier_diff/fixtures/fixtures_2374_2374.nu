const VERIFIER_DIFF_FIXTURES_2374_2374 = [
    {
        name: "cpumap-map-delete-rejects-redirect-map-kind"
        category: "maps"
        tags: [maps cpumap map-delete diagnostics reject redirect-map]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete cpu_targets --kind cpumap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind cpumap is reserved for bpf_redirect_map"
    }
]
