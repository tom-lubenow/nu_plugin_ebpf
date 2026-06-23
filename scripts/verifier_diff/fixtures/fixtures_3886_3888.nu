const VERIFIER_DIFF_FIXTURES_3886_3888 = [
    {
        name: "helper-redirect-map-rejects-missing-kind"
        category: "helper-state"
        tags: [redirect-map helper-call map diagnostics reject xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_map" tx_ports 0 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind devmap, --kind devmap-hash, --kind cpumap, or --kind xskmap"
    }
    {
        name: "helper-redirect-map-rejects-unknown-kind"
        category: "helper-state"
        tags: [redirect-map helper-call map diagnostics reject xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_map" tx_ports 0 0 --kind mystery-map-kind'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind must be one of: devmap, devmap-hash, cpumap, xskmap"
    }
    {
        name: "helper-redirect-map-rejects-unsupported-kind"
        category: "helper-state"
        tags: [redirect-map helper-call map diagnostics reject xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_map" tx_ports 0 0 --kind hash'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind devmap, --kind devmap-hash, --kind cpumap, or --kind xskmap, got hash"
    }
]
