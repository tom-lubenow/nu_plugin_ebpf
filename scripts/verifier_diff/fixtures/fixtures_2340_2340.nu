const VERIFIER_DIFF_FIXTURES_2340_2340 = [
    {
        name: "map-define-value-type-top-level-dynptr-rejects-context"
        category: "maps"
        tags: [maps map-define dynptr diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "bpf_dynptr"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value dynptr type spec 'bpf_dynptr' is not supported; bpf_dynptr objects are stack-only verifier state"
    }
]
