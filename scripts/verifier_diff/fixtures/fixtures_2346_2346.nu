const VERIFIER_DIFF_FIXTURES_2346_2346 = [
    {
        name: "map-define-bpf-spin-lock-multiple-fields-rejects-single-lock"
        category: "maps"
        tags: [maps map-define bpf_spin_lock records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,other:bpf_spin_lock}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "exactly one bpf_spin_lock"
    }
]
