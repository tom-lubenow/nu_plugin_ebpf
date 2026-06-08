const VERIFIER_DIFF_FIXTURES_2376_2376 = [
    {
        name: "devmap-hash-map-delete-rejects-redirect-map-kind"
        category: "maps"
        tags: [maps devmap-hash map-delete diagnostics reject redirect-map]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete devices_by_ifindex --kind devmap-hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind devmap-hash is reserved for bpf_redirect_map"
    }
]
