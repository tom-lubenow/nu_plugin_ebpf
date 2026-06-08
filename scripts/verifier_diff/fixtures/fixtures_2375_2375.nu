const VERIFIER_DIFF_FIXTURES_2375_2375 = [
    {
        name: "devmap-map-delete-rejects-redirect-map-kind"
        category: "maps"
        tags: [maps devmap map-delete diagnostics reject redirect-map]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete devices --kind devmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind devmap is reserved for bpf_redirect_map"
    }
]
