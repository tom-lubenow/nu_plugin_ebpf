const VERIFIER_DIFF_FIXTURES_3883_3885 = [
    {
        name: "helper-timer-init-rejects-missing-kind"
        category: "helper-state"
        tags: [timer helper-call map diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer other_timers 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind hash, --kind array, or --kind lru-hash for bpf_timer_init"
    }
    {
        name: "helper-timer-init-rejects-unknown-kind"
        category: "helper-state"
        tags: [timer helper-call map diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer other_timers 0 --kind mystery-map-kind'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind must be one of: hash, array, lru-hash"
    }
    {
        name: "helper-timer-init-rejects-unsupported-kind"
        category: "helper-state"
        tags: [timer helper-call map diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer other_timers 0 --kind per-cpu-array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_timer_init; supported kinds are hash, array, and lru-hash"
    }
]
