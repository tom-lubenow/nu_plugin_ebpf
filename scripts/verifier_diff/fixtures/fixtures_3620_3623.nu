export const VERIFIER_DIFF_FIXTURES_3620_3623 = [
    {
        name: "map-define-per-cpu-hash-array-record-list-field-value-put-get-tail-element"
        category: "maps"
        tags: [maps per-cpu-hash map-define records arrays list value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_sample_batches --kind per-cpu-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put cpu_sample_batches 0 --kind per-cpu-hash'
            '  let entries = (0 | map-get cpu_sample_batches --kind per-cpu-hash)'
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
        name: "map-define-per-cpu-hash-array-record-string-field-value-put-get-tail-length"
        category: "maps"
        tags: [maps per-cpu-hash map-define records arrays string value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_name_batches --kind per-cpu-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | map-put cpu_name_batches 0 --kind per-cpu-hash'
            '  let entries = (0 | map-get cpu_name_batches --kind per-cpu-hash)'
            '  if $entries {'
            '    let row = ($entries | get 1)'
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
        name: "map-define-lru-per-cpu-hash-array-record-list-field-value-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays list value-type map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_sample_batches --kind lru-per-cpu-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put lru_cpu_sample_batches 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_sample_batches --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lru-per-cpu-hash-array-record-string-builder-value-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays string append value-type map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_name_batches --kind lru-per-cpu-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-put lru_cpu_name_batches 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_name_batches --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
