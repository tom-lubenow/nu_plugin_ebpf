export const VERIFIER_DIFF_FIXTURES_3612_3615 = [
    {
        name: "map-define-array-record-list-field-source-key-put-get"
        category: "maps"
        tags: [maps map-define records arrays list key-type source-key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_batches --kind hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  42 | map-put source_keyed_batches [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] --kind hash'
            '  let entry = ([{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-get source_keyed_batches --kind hash)'
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
        name: "map-define-array-record-string-field-source-key-put"
        category: "maps"
        tags: [maps map-define records arrays string key-type source-key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_names --kind hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  42 | map-put source_keyed_names [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] --kind hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-list-builder-source-key-put-get"
        category: "maps"
        tags: [maps map-define records arrays list append key-type source-key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_batches_build --kind hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  let key = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  42 | map-put source_keyed_batches_build $key --kind hash'
            '  let entry = ($key | map-get source_keyed_batches_build --kind hash)'
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
        name: "map-define-array-record-spread-string-source-key-put"
        category: "maps"
        tags: [maps map-define records arrays string list-spread key-type source-key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define source_keyed_names_spread --kind hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  let key = [{ id: 1 name: "aa" }, ...$tail]'
            '  42 | map-put source_keyed_names_spread $key --kind hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
