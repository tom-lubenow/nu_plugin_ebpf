const PROGRAM_MAP_REDIRECT_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '  redirect-map tx_hash 0 --kind devmap-hash'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '  redirect-map xsks 0 --kind xskmap'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_DEVMAP"
            "map:BPF_MAP_TYPE_DEVMAP_HASH"
            "map:BPF_MAP_TYPE_CPUMAP"
            "map:BPF_MAP_TYPE_XSKMAP"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_SOCKMAP"
            "map:BPF_MAP_TYPE_SOCKHASH"
            "map:BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_DEVMAP_HASH"]
    }
]
