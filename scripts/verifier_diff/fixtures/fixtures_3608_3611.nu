export const VERIFIER_DIFF_FIXTURES_3608_3611 = [
    {
        name: "map-define-array-record-list-field-value-put-get-tail-element"
        category: "maps"
        tags: [maps map-define records arrays list value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_batches --kind hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put sample_batches 0 --kind hash'
            '  let entries = (0 | map-get sample_batches --kind hash)'
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
        name: "map-define-array-record-string-field-value-put-get-tail-length"
        category: "maps"
        tags: [maps map-define records arrays string value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_batches --kind hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | map-put name_batches 0 --kind hash'
            '  let entries = (0 | map-get name_batches --kind hash)'
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
        name: "map-define-array-record-list-builder-list-field-value-put-get-tail-element"
        category: "maps"
        tags: [maps map-define records arrays list append value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_batches_build --kind hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put sample_batches_build 0 --kind hash'
            '  let stored = (0 | map-get sample_batches_build --kind hash)'
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
        name: "map-define-array-record-spread-string-field-value-put-get-tail-length"
        category: "maps"
        tags: [maps map-define records arrays string list-spread value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define name_batches_spread --kind hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put name_batches_spread 0 --kind hash'
            '  let stored = (0 | map-get name_batches_spread --kind hash)'
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
