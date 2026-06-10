const VERIFIER_DIFF_FIXTURES_0219_0250 = [
    {
        name: "netfilter-defrag-target-metadata"
        category: "program-model"
        tags: [netfilter metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-target-metadata"
        category: "program-model"
        tags: [lwt metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-migrate-target-metadata"
        category: "program-model"
        tags: [sk-reuseport metadata migrate]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-target-metadata"
        category: "program-model"
        tags: [cgroup-sock-addr metadata unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "syscall-target-metadata"
        category: "program-model"
        tags: [syscall metadata]
        target: "syscall:demo"
        program: [
            '{||'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-target-metadata"
        category: "program-model"
        tags: [freplace metadata]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-vma-target-metadata"
        category: "program-model"
        tags: [iter metadata task-vma]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
