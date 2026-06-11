export const VERIFIER_DIFF_FIXTURES_3648_3651 = [
    {
        name: "map-define-lpm-trie-record-key-array-record-list-field-value-put-get-tail-element"
        category: "maps"
        tags: [maps lpm-trie map-define global-define records arrays list value-type key-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lpm_sample_batches --kind lpm-trie --key-type "record{prefix:u32,addr:u32}" --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  { prefix: 32 addr: 16909060 } | global-define --type "record{prefix:u32,addr:u32}" lpm_key'
            '  let key = (global-get lpm_key)'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put lpm_sample_batches $key --kind lpm-trie'
            '  let entries = ($key | map-get lpm_sample_batches --kind lpm-trie)'
            '  if $entries {'
            '    let row = ($entries | get 1)'
            '    (($row.id == 2) and (($row.samples | get 0) == 3))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lpm-trie-record-key-array-record-string-builder-value-put-get-tail-length"
        category: "maps"
        tags: [maps lpm-trie map-define global-define records arrays string append value-type key-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lpm_name_batches --kind lpm-trie --key-type "record{prefix:u32,addr:u32}" --value-type "array{record{id:int,name:string:15}:2}"'
            '  { prefix: 32 addr: 16909060 } | global-define --type "record{prefix:u32,addr:u32}" lpm_name_key'
            '  let key = (global-get lpm_name_key)'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-put lpm_name_batches $key --kind lpm-trie'
            '  let stored = ($key | map-get lpm_name_batches --kind lpm-trie)'
            '  if $stored {'
            '    let row = ($stored | get 1)'
            '    (($row.id == 2) and (($row.name | str length) == 3))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lpm-trie-record-key-array-record-list-field-value-contains-delete"
        category: "maps"
        tags: [maps lpm-trie map-define global-define records arrays list value-type key-type map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lpm_sample_batches_ops --kind lpm-trie --key-type "record{prefix:u32,addr:u32}" --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  { prefix: 32 addr: 16909060 } | global-define --type "record{prefix:u32,addr:u32}" lpm_ops_key'
            '  let key = (global-get lpm_ops_key)'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put lpm_sample_batches_ops $key --kind lpm-trie'
            '  if (map-contains lpm_sample_batches_ops $key --kind lpm-trie) {'
            '    map-delete lpm_sample_batches_ops $key --kind lpm-trie'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lpm-trie-record-key-array-record-spread-string-value-put-delete"
        category: "maps"
        tags: [maps lpm-trie map-define global-define records arrays string list-spread value-type key-type map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lpm_name_batches_spread --kind lpm-trie --key-type "record{prefix:u32,addr:u32}" --value-type "array{record{id:int,name:string:15}:2}"'
            '  { prefix: 32 addr: 16909060 } | global-define --type "record{prefix:u32,addr:u32}" lpm_spread_key'
            '  let key = (global-get lpm_spread_key)'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put lpm_name_batches_spread $key --kind lpm-trie'
            '  map-delete lpm_name_batches_spread $key --kind lpm-trie'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
