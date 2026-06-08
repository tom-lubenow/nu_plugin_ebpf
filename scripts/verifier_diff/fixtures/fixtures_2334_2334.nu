const VERIFIER_DIFF_FIXTURES_2334_2334 = [
    {
        name: "map-define-value-type-dynptr-field-rejects-path"
        category: "maps"
        tags: [maps map-define records dynptr diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "record{dptr:bpf_dynptr,counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'dptr' type spec 'bpf_dynptr' is not supported; bpf_dynptr objects are stack-only verifier state"
    }
]
