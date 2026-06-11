export const VERIFIER_DIFF_FIXTURES_3640_3643 = [
    {
        name: "map-define-lru-hash-array-record-list-field-value-put-get-tail-element"
        category: "maps"
        tags: [maps lru-hash map-define records arrays list value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_sample_batches --kind lru-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put lru_sample_batches 0 --kind lru-hash'
            '  let entries = (0 | map-get lru_sample_batches --kind lru-hash)'
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
        name: "map-define-lru-hash-array-record-string-builder-value-put-get-tail-length"
        category: "maps"
        tags: [maps lru-hash map-define records arrays string append value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_name_batches --kind lru-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-put lru_name_batches 0 --kind lru-hash'
            '  let stored = (0 | map-get lru_name_batches --kind lru-hash)'
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
        name: "map-define-lru-hash-array-record-list-field-key-put-get"
        category: "maps"
        tags: [maps lru-hash map-define global-define records arrays list key-type map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_keyed_batches --kind lru-hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" lru_key_entries'
            '  let key = (global-get lru_key_entries)'
            '  42 | map-put lru_keyed_batches $key --kind lru-hash'
            '  let entry = ($key | map-get lru_keyed_batches --kind lru-hash)'
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
        name: "map-define-lru-hash-array-record-string-builder-source-key-contains-delete"
        category: "maps"
        tags: [maps lru-hash map-define records arrays string append key-type source-key map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_source_keyed_names --kind lru-hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let key = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  42 | map-put lru_source_keyed_names $key --kind lru-hash'
            '  if (map-contains lru_source_keyed_names $key --kind lru-hash) {'
            '    map-delete lru_source_keyed_names $key --kind lru-hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
