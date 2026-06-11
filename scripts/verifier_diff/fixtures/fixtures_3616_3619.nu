export const VERIFIER_DIFF_FIXTURES_3616_3619 = [
    {
        name: "map-define-array-record-list-field-source-key-contains"
        category: "maps"
        tags: [maps map-define records arrays list key-type source-key map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_batches_ops --kind hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  if (map-contains source_keyed_batches_ops [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] --kind hash) {'
            '    1'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-list-builder-source-key-contains-delete"
        category: "maps"
        tags: [maps map-define records arrays list append key-type source-key map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_batches_build_ops --kind hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  let key = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  42 | map-put source_keyed_batches_build_ops $key --kind hash'
            '  if (map-contains source_keyed_batches_build_ops $key --kind hash) {'
            '    map-delete source_keyed_batches_build_ops $key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-string-builder-source-key-contains-delete"
        category: "maps"
        tags: [maps map-define records arrays string append key-type source-key map-put map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_names_build_ops --kind hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let key = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  42 | map-put source_keyed_names_build_ops $key --kind hash'
            '  if (map-contains source_keyed_names_build_ops $key --kind hash) {'
            '    map-delete source_keyed_names_build_ops $key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-string-field-source-key-contains"
        category: "maps"
        tags: [maps map-define records arrays string key-type source-key map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_names_contains --kind hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  if (map-contains source_keyed_names_contains [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] --kind hash) {'
            '    1'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
