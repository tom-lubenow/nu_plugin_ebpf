export const VERIFIER_DIFF_FIXTURES_3636_3639 = [
    {
        name: "map-push-stack-array-record-list-field-get-tail-element"
        category: "maps"
        tags: [maps records arrays stack list map-push map-pop get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-push stack_entry_batches --kind stack'
            '  let entries = (map-pop stack_entry_batches --kind stack)'
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
        name: "map-push-stack-array-record-string-field-get-tail-length"
        category: "maps"
        tags: [maps records arrays stack string map-push map-pop get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | map-push stack_name_batches --kind stack'
            '  let entries = (map-pop stack_name_batches --kind stack)'
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
        name: "map-push-stack-array-record-list-builder-get-tail-element"
        category: "maps"
        tags: [maps records arrays stack list append map-push map-pop get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-push stack_entry_batches_build --kind stack'
            '  let stored = (map-pop stack_entry_batches_build --kind stack)'
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
        name: "map-push-stack-array-record-spread-string-field-get-tail-length"
        category: "maps"
        tags: [maps records arrays stack string list-spread map-push map-pop get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-push stack_name_batches_spread --kind stack'
            '  let stored = (map-pop stack_name_batches_spread --kind stack)'
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
