const VERIFIER_DIFF_FIXTURES_2411_2411 = [
    {
        name: "arena-map-define-rejects-missing-max-entries"
        category: "maps"
        tags: [maps arena map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define arena_space --kind arena'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind arena requires --max-entries"
    }
    {
        name: "arena-map-define-object-accepts-map-extra"
        category: "maps"
        tags: [maps arena map-define map-extra accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define arena_pages --kind arena --max-entries 64 --map-extra 0x100000000'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
