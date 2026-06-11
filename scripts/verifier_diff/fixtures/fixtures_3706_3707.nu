export const VERIFIER_DIFF_FIXTURES_3706_3707 = [
    {
        name: "callback-for-each-map-elem-hash-array-record-string-value-tail-length"
        category: "callbacks"
        tags: [helper-call callback map hash records arrays string str length get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_hash_names_len --kind hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  helper-call "bpf_for_each_map_elem" callback_hash_names_len {|m k v cb|'
            '    let row = ($v | get 1)'
            '    ($row.name | str length) | count'
            '    0'
            '  } "ctx" 0 --kind hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem-per-cpu-array-record-string-value-tail-length"
        category: "callbacks"
        tags: [helper-call callback map per-cpu-array records arrays string str length get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define callback_percpu_array_names_len --kind per-cpu-array --value-type "array{record{id:int,name:string:15}:2}" --max-entries 1'
            '  helper-call "bpf_for_each_map_elem" callback_percpu_array_names_len {|m k v cb|'
            '    let row = ($v | get 1)'
            '    ($row.name | str length) | count'
            '    0'
            '  } "ctx" 0 --kind per-cpu-array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
