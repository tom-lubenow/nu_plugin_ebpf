const VERIFIER_DIFF_FIXTURES_2402_2402 = [
    {
        name: "devmap-map-define-rejects-redirect-map-kind"
        category: "maps"
        tags: [maps devmap map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define devices --kind devmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind devmap is reserved for redirect-map / bpf_redirect_map"
    }
]
