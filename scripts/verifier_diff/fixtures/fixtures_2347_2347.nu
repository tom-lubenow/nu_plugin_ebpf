const VERIFIER_DIFF_FIXTURES_2347_2347 = [
    {
        name: "map-define-graph-root-nested-record-rejects-top-level"
        category: "maps"
        tags: [maps map-define graph-roots records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{nested:record{root:bpf_rb_root:node_data:node},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "graph roots must be top-level map-value record fields"
    }
]
