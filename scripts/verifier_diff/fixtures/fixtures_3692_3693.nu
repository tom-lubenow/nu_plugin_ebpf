export const VERIFIER_DIFF_FIXTURES_3692_3693 = [
    {
        name: "map-define-lpm-trie-record-key-array-record-list-builder-value-put-get-tail-element"
        category: "maps"
        tags: [maps lpm-trie map-define global-define records arrays list append value-type key-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lpm_sample_batches_build --kind lpm-trie --key-type "record{prefix:u32,addr:u32}" --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  { prefix: 32 addr: 16909060 } | global-define --type "record{prefix:u32,addr:u32}" lpm_build_key'
            '  let key = (global-get lpm_build_key)'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put lpm_sample_batches_build $key --kind lpm-trie'
            '  let stored = ($key | map-get lpm_sample_batches_build --kind lpm-trie)'
            '  if $stored {'
            '    let row = ($stored | get 1)'
            '    (($row.id == 2) and (($row.samples | get 1) == 4))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lpm-trie-record-key-array-record-list-builder-value-put-delete"
        category: "maps"
        tags: [maps lpm-trie map-define global-define records arrays list append value-type key-type map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lpm_sample_batches_build_delete --kind lpm-trie --key-type "record{prefix:u32,addr:u32}" --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  { prefix: 32 addr: 16909060 } | global-define --type "record{prefix:u32,addr:u32}" lpm_build_delete_key'
            '  let key = (global-get lpm_build_delete_key)'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put lpm_sample_batches_build_delete $key --kind lpm-trie'
            '  map-delete lpm_sample_batches_build_delete $key --kind lpm-trie'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
