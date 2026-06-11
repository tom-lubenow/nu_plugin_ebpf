export const VERIFIER_DIFF_FIXTURES_3680_3683 = [
    {
        name: "map-define-lru-hash-array-record-list-builder-value-put-get-tail-element"
        category: "maps"
        tags: [maps lru-hash map-define records arrays list append value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_sample_batches_build --kind lru-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put lru_sample_batches_build 0 --kind lru-hash'
            '  let stored = (0 | map-get lru_sample_batches_build --kind lru-hash)'
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
        name: "map-define-lru-hash-array-record-string-spread-value-put-get-tail-length"
        category: "maps"
        tags: [maps lru-hash map-define records arrays string list-spread value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_name_batches_spread --kind lru-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put lru_name_batches_spread 0 --kind lru-hash'
            '  let stored = (0 | map-get lru_name_batches_spread --kind lru-hash)'
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
        name: "map-define-lru-per-cpu-hash-array-record-list-builder-value-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays list append value-type map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_sample_batches_build --kind lru-per-cpu-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put lru_cpu_sample_batches_build 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_sample_batches_build --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lru-per-cpu-hash-array-record-string-spread-value-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays string list-spread value-type map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_name_batches_spread --kind lru-per-cpu-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put lru_cpu_name_batches_spread 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_name_batches_spread --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
