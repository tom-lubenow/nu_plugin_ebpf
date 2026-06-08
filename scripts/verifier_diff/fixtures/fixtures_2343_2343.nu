const VERIFIER_DIFF_FIXTURES_2343_2343 = [
    {
        name: "map-define-bpf-spin-lock-nested-record-rejects-top-level"
        category: "maps"
        tags: [maps map-define bpf_spin_lock records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{nested:record{lock:bpf_spin_lock},counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_spin_lock must be a top-level map-value record field"
    }
]
