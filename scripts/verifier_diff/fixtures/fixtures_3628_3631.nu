export const VERIFIER_DIFF_FIXTURES_3628_3631 = [
    {
        name: "map-define-array-map-array-record-list-field-value-put-get-tail-element"
        category: "maps"
        tags: [maps array map-define records arrays list value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define array_sample_batches --kind array --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 1'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put array_sample_batches 0 --kind array'
            '  let entries = (0 | map-get array_sample_batches --kind array)'
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
        name: "map-define-array-map-array-record-string-field-value-put-get-tail-length"
        category: "maps"
        tags: [maps array map-define records arrays string value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define array_name_batches --kind array --value-type "array{record{id:int,name:string:15}:2}" --max-entries 1'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | map-put array_name_batches 0 --kind array'
            '  let entries = (0 | map-get array_name_batches --kind array)'
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
        name: "map-define-array-map-array-record-list-builder-value-put-get-tail-element"
        category: "maps"
        tags: [maps array map-define records arrays list append value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define array_sample_batches_build --kind array --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 1'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put array_sample_batches_build 0 --kind array'
            '  let stored = (0 | map-get array_sample_batches_build --kind array)'
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
        name: "map-define-array-map-array-record-spread-string-value-put-get-tail-length"
        category: "maps"
        tags: [maps array map-define records arrays string list-spread value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define array_name_batches_spread --kind array --value-type "array{record{id:int,name:string:15}:2}" --max-entries 1'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put array_name_batches_spread 0 --kind array'
            '  let stored = (0 | map-get array_name_batches_spread --kind array)'
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
]
