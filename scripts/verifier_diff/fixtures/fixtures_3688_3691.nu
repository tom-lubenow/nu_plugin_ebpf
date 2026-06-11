export const VERIFIER_DIFF_FIXTURES_3688_3691 = [
    {
        name: "map-define-lru-hash-array-record-list-builder-source-key-contains-delete"
        category: "maps"
        tags: [maps lru-hash map-define records arrays list append key-type source-key map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_source_keyed_batches_build --kind lru-hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  let key = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  42 | map-put lru_source_keyed_batches_build $key --kind lru-hash'
            '  if (map-contains lru_source_keyed_batches_build $key --kind lru-hash) {'
            '    map-delete lru_source_keyed_batches_build $key --kind lru-hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lru-hash-array-record-string-spread-source-key-put"
        category: "maps"
        tags: [maps lru-hash map-define records arrays string list-spread key-type source-key map-put accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_source_keyed_names_spread --kind lru-hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  let key = [{ id: 1 name: "aa" }, ...$tail]'
            '  42 | map-put lru_source_keyed_names_spread $key --kind lru-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lru-per-cpu-hash-array-record-list-builder-source-key-contains-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays list append key-type source-key map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_source_keyed_batches_build --kind lru-per-cpu-hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  let key = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  42 | map-put lru_cpu_source_keyed_batches_build $key --kind lru-per-cpu-hash'
            '  if (map-contains lru_cpu_source_keyed_batches_build $key --kind lru-per-cpu-hash) {'
            '    map-delete lru_cpu_source_keyed_batches_build $key --kind lru-per-cpu-hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-lru-per-cpu-hash-array-record-string-spread-source-key-put"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-define records arrays string list-spread key-type source-key map-put accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define lru_cpu_source_keyed_names_spread --kind lru-per-cpu-hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  let key = [{ id: 1 name: "aa" }, ...$tail]'
            '  42 | map-put lru_cpu_source_keyed_names_spread $key --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
