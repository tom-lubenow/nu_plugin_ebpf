const VERIFIER_DIFF_FIXTURES_2338_2338 = [
    {
        name: "map-define-value-type-graph-payload-nested-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph records bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb:record{nested:record{refs:array{bpf_refcount:2}},cookie:u64},counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root.nested.refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
]
