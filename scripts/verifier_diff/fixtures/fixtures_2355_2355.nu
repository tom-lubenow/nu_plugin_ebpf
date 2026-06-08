const VERIFIER_DIFF_FIXTURES_2355_2355 = [
    {
        name: "xskmap-map-delete-rejects-kind"
        category: "maps"
        tags: [maps xskmap map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete xsks --kind xskmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind xskmap is reserved for bpf_redirect_map"
    }
]
