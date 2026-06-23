const VERIFIER_DIFF_FIXTURES_3880_3882 = [
    {
        name: "raw-map-peek-helper-rejects-missing-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-peek diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_peek_elem" recent_raw $value'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind queue, --kind stack, or --kind bloom-filter"
    }
    {
        name: "raw-map-peek-helper-rejects-unknown-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-peek diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_peek_elem" recent_raw $value --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind must be one of: queue, stack, bloom-filter"
    }
    {
        name: "raw-map-peek-helper-rejects-unsupported-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-peek diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_peek_elem" recent_raw $value --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind queue, --kind stack, or --kind bloom-filter, got hash"
    }
]
