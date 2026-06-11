export const VERIFIER_DIFF_FIXTURES_3624_3627 = [
    {
        name: "map-define-per-cpu-hash-array-record-list-field-key-put-get"
        category: "maps"
        tags: [maps per-cpu-hash map-define global-define records arrays list key-type map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_keyed_batches --kind per-cpu-hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" cpu_key_entries'
            '  let key = (global-get cpu_key_entries)'
            '  42 | map-put cpu_keyed_batches $key --kind per-cpu-hash'
            '  let entry = ($key | map-get cpu_keyed_batches --kind per-cpu-hash)'
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
        name: "map-define-per-cpu-hash-array-record-string-field-key-put-get"
        category: "maps"
        tags: [maps per-cpu-hash map-define global-define records arrays string key-type map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_keyed_names --kind per-cpu-hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" cpu_key_names'
            '  let key = (global-get cpu_key_names)'
            '  42 | map-put cpu_keyed_names $key --kind per-cpu-hash'
            '  let entry = ($key | map-get cpu_keyed_names --kind per-cpu-hash)'
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
        name: "map-define-lru-per-cpu-hash-array-record-list-field-key-contains-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define global-define records arrays list key-type map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_keyed_batches --kind lru-per-cpu-hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" lru_cpu_key_entries'
            '  let key = (global-get lru_cpu_key_entries)'
            '  42 | map-put lru_cpu_keyed_batches $key --kind lru-per-cpu-hash'
            '  if (map-contains lru_cpu_keyed_batches $key --kind lru-per-cpu-hash) {'
            '    map-delete lru_cpu_keyed_batches $key --kind lru-per-cpu-hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lru-per-cpu-hash-array-record-string-builder-source-key-contains-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays string append key-type source-key map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_source_keyed_names --kind lru-per-cpu-hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let key = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  42 | map-put lru_cpu_source_keyed_names $key --kind lru-per-cpu-hash'
            '  if (map-contains lru_cpu_source_keyed_names $key --kind lru-per-cpu-hash) {'
            '    map-delete lru_cpu_source_keyed_names $key --kind lru-per-cpu-hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
