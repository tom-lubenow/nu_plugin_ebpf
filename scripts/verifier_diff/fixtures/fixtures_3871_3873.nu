const VERIFIER_DIFF_FIXTURES_3871_3873 = [
    {
        name: "helper-map-lookup-percpu-rejects-missing-kind"
        category: "helpers"
        tags: [helper-call map per-cpu diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = (helper-call "bpf_map_lookup_percpu_elem" cpu_seen 0 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind per-cpu-hash, --kind per-cpu-array, or --kind lru-per-cpu-hash"
    }
    {
        name: "helper-map-lookup-percpu-rejects-unknown-kind"
        category: "helpers"
        tags: [helper-call map per-cpu diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = (helper-call "bpf_map_lookup_percpu_elem" cpu_seen 0 0 --kind mystery-map-kind)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind must be one of: per-cpu-hash, per-cpu-array, lru-per-cpu-hash"
    }
    {
        name: "helper-map-lookup-percpu-rejects-unsupported-kind"
        category: "helpers"
        tags: [helper-call map per-cpu diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = (helper-call "bpf_map_lookup_percpu_elem" cpu_seen 0 0 --kind hash)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --kind per-cpu-hash, --kind per-cpu-array, or --kind lru-per-cpu-hash, got hash"
    }
]
