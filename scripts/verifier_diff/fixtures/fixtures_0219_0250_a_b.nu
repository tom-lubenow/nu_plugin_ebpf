const VERIFIER_DIFF_FIXTURES_0219_0250_A_B = [
    {
        name: "map-put-get-null-checked"
        category: "maps"
        tags: [hash-map null-check]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash'
            '  let entry = (0 | map-get seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-direct-pointer-branch"
        category: "maps"
        tags: [hash-map null-check branch]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put direct_seen_args 0 --kind hash'
            '  let entry = (0 | map-get direct_seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-record-key-put-get"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed --kind hash --key-type "record{pid:int,cookie:int}" --value-type int'
            '  let key = { pid: 1, cookie: 7 }'
            '  42 | map-put keyed $key --kind hash'
            '  let entry = ($key | map-get keyed --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-aligned-record-key-put-get"
        category: "maps"
        tags: [maps map-define records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_aligned --kind hash --key-type "record{tag:int,flag:bool}" --value-type int'
            '  let key = { tag: 7, flag: true }'
            '  42 | map-put keyed_aligned $key --kind hash'
            '  let entry = ($key | map-get keyed_aligned --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-key-put-get"
        category: "maps"
        tags: [maps map-define records arrays map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches --kind hash --key-type "array{record{pid:int,cpu:int}:2}" --value-type int'
            '  let put_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  42 | map-put keyed_batches $put_key --kind hash'
            '  let get_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  let entry = ($get_key | map-get keyed_batches --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-key-contains-delete"
        category: "maps"
        tags: [maps map-define records arrays map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches_ops --kind hash --key-type "array{record{pid:int,cpu:int}:2}" --value-type int'
            '  let put_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  42 | map-put keyed_batches_ops $put_key --kind hash'
            '  let contains_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '  if (map-contains keyed_batches_ops $contains_key --kind hash) {'
            '    let delete_key = [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }]'
            '    map-delete keyed_batches_ops $delete_key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-value-type-invalid-array-length-rejects-context"
        category: "maps"
        tags: [maps map-define arrays diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define bad_values --kind hash --value-type "array{u32:x}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'array{u32:x}' has an invalid array length"
    }
    {
        name: "map-define-graph-root-payload-unmatched-braces-rejects-context"
        category: "maps"
        tags: [maps map-define graph diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "bpf_list_head:node_data:node:record{refs:bpf_refcount"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value type spec 'bpf_list_head:node_data:node:record{refs:bpf_refcount' has unmatched '{' braces"
    }
    {
        name: "map-define-value-type-invalid-graph-root-field-rejects-path"
        category: "maps"
        tags: [maps map-define graph records diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node-field,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "record field 'root' type spec 'bpf_list_head:node_data:node-field' requires a valid node field name"
    }
]
