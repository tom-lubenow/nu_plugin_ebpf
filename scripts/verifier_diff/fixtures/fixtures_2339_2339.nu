const VERIFIER_DIFF_FIXTURES_2339_2339 = [
    {
        name: "map-define-value-type-invalid-graph-object-type-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_rb_root:rb-item:rb,counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_rb_root:rb-item:rb' requires a named object type"
    }
]
