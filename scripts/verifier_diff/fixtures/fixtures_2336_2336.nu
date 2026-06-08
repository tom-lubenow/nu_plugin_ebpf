const VERIFIER_DIFF_FIXTURES_2336_2336 = [
    {
        name: "map-define-value-type-graph-payload-duplicate-node-field-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{node:u64,cookie:u64}}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node:record{node:u64,cookie:u64}' object payload duplicates node field"
    }
]
