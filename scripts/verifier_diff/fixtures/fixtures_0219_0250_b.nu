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
    {
        name: "annotated-mut-record-alignment"
        category: "globals"
        tags: [globals records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<tag: bool count: int> = { tag: true, count: 7 }'
            '  $state.count | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-empty-zero-init"
        category: "globals"
        tags: [globals records zero-init accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-scalar-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals scalar "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = null'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected int, found nothing"
    }
    {
        name: "annotated-mut-record-null-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records "null" parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = null'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found nothing"
    }
    {
        name: "annotated-mut-record-nested-empty-zero-fill"
        category: "globals"
        tags: [globals records zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 stats: {} }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-nested-extra-field-rejects-path"
        category: "globals"
        tags: [globals records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<stats: record<hits: int>> = { stats: { hits: 7 extra: true } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unexpected record field 'stats.extra'"
    }
    {
        name: "annotated-mut-list-spread-initializer"
        category: "globals"
        tags: [globals list list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut vals: list<int> = [1, ...[2, 3]]'
            '  ($vals | get 2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-string-field-count"
        category: "globals"
        tags: [globals records string accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<comm: string pid: int> = { comm: "hi" pid: 7 }'
            '  $state.comm | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-inline-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...[{ pid: 9 cpu: 3 }]]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-record-array-bound-spread-initializer"
        category: "globals"
        tags: [globals records arrays list-spread accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  mut entries: list<record<pid: int cpu: int>> = [{ pid: 7 cpu: 2 }, ...$tail]'
            '  $entries.1.cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "annotated-mut-top-level-record-omission-rejected-by-nushell-parser"
        category: "globals"
        tags: [globals records parser reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = { pid: 7 }'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expected record<pid: int, stats: record<hits: int, ok: bool>>, found record<pid: int>"
    }
]
