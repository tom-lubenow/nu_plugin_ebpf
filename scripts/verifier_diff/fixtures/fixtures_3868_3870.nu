const VERIFIER_DIFF_FIXTURES_3868_3870 = [
    {
        name: "callback-for-each-map-elem-rejects-missing-kind"
        category: "callbacks"
        tags: [helper-call callback map diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind hash, array, lru-hash, per-cpu-hash, per-cpu-array, or lru-per-cpu-hash for bpf_for_each_map_elem"
    }
    {
        name: "callback-for-each-map-elem-rejects-unknown-kind"
        category: "callbacks"
        tags: [helper-call callback map diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" 0 --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_for_each_map_elem supports hash, array, lru-hash, per-cpu-hash, per-cpu-array, and lru-per-cpu-hash"
    }
    {
        name: "callback-for-each-map-elem-rejects-unsupported-kind"
        category: "callbacks"
        tags: [helper-call callback map diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    0'
            '  } "ctx" 0 --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "supported kinds are hash, array, lru-hash, per-cpu-hash, per-cpu-array, and lru-per-cpu-hash"
    }
]
