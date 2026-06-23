const VERIFIER_DIFF_FIXTURES_3874_3879 = [
    {
        name: "raw-map-push-helper-rejects-missing-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-push diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind queue, --kind stack, or --kind bloom-filter"
    }
    {
        name: "raw-map-push-helper-rejects-unknown-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-push diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 0 --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind must be one of: queue, stack, bloom-filter"
    }
    {
        name: "raw-map-push-helper-rejects-unsupported-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-push diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind queue, --kind stack, or --kind bloom-filter, got hash"
    }
    {
        name: "raw-map-pop-helper-rejects-missing-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-pop diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_pop_elem" recent_raw $value'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind queue or --kind stack"
    }
    {
        name: "raw-map-pop-helper-rejects-unknown-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-pop diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_pop_elem" recent_raw $value --kind mystery-map-kind'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind must be one of: queue, stack"
    }
    {
        name: "raw-map-pop-helper-rejects-unsupported-kind"
        category: "maps"
        tags: [maps queue stack helper-call map-pop diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_pop_elem" recent_raw $value --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind queue or --kind stack, got hash"
    }
]
