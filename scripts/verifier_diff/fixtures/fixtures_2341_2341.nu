const VERIFIER_DIFF_FIXTURES_2341_2341 = [
    {
        name: "map-define-bpf-timer-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define timer diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind queue --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_timer, which is only supported for hash, array, and lru-hash maps"
    }
]
