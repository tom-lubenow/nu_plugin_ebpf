export const VERIFIER_DIFF_FIXTURES_3698_3701 = [
    {
        name: "callback-for-each-map-elem-array-record-string-value-tail-id"
        category: "callbacks"
        tags: [helper-call callback map array records arrays string get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_array_names --kind array --value-type "array{record{id:int,name:string:15}:2}" --max-entries 1'
            '  helper-call "bpf_for_each_map_elem" callback_array_names {|m k v cb|'
            '    let row = ($v | get 1)'
            '    $row.id | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-hash-array-record-list-value-tail-element"
        category: "callbacks"
        tags: [helper-call callback map hash records arrays list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_hash_batches --kind hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  helper-call "bpf_for_each_map_elem" callback_hash_batches {|m k v cb|'
            '    let row = ($v | get 1)'
            '    ($row.samples | get 1) | count'
            '    0'
            '  } "ctx" 0 --kind hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-lru-hash-array-record-list-value-tail-element"
        category: "callbacks"
        tags: [helper-call callback map lru-hash records arrays list get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_lru_batches --kind lru-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  helper-call "bpf_for_each_map_elem" callback_lru_batches {|m k v cb|'
            '    let row = ($v | get 1)'
            '    ($row.samples | get 0) | count'
            '    0'
            '  } "ctx" 0 --kind lru-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-per-cpu-hash-array-record-string-value-tail-id"
        category: "callbacks"
        tags: [helper-call callback map per-cpu-hash records arrays string get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_cpu_hash_names --kind per-cpu-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  helper-call "bpf_for_each_map_elem" callback_cpu_hash_names {|m k v cb|'
            '    let row = ($v | get 1)'
            '    $row.id | count'
            '    0'
            '  } "ctx" 0 --kind per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
