const VERIFIER_DIFF_FIXTURES_2344_2344 = [
    {
        name: "map-define-bpf-refcount-nested-record-rejects-top-level"
        category: "maps"
        tags: [maps map-define bpf_refcount records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind hash --value-type "record{nested:record{refs:bpf_refcount},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_refcount must be a top-level map-value record field"
    }
]
