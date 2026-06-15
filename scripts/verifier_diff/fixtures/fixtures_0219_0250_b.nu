const VERIFIER_DIFF_FIXTURES_0219_0250_B = [
    {
        name: "map-define-value-type-graph-root-payload-non-record-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:u64,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node:u64' requires the object payload schema to be record{...}"
    }
    {
        name: "map-define-value-type-graph-root-payload-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph records bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64},count:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root.refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
    {
        name: "map-define-value-type-top-level-graph-root-payload-refcount-array-rejects-path"
        category: "maps"
        tags: [maps map-define graph bpf_refcount diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'refs' type spec 'array{bpf_refcount:2}' has bpf_refcount, but arrays of verifier-managed bpf_refcount fields are not supported"
    }
    {
        name: "map-define-key-type-duplicate-record-field-rejects-path"
        category: "maps"
        tags: [maps map-define records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define dup_keys --kind hash --key-type "record{pid:u32,pid:u64}" --value-type int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'pid' is duplicated in type spec 'record{pid:u32,pid:u64}'"
    }
    {
        name: "map-define-value-type-invalid-kptr-field-rejects-path"
        category: "maps"
        tags: [maps map-define records kptr diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define state --kind hash --value-type "record{task:kptr:task-struct}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'task' type spec 'kptr:task-struct' requires a kernel struct type name"
    }
]
