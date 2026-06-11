export const VERIFIER_DIFF_FIXTURES_3600_3603 = [
    {
        name: "map-put-array-record-list-field-get-tail-element"
        category: "maps"
        tags: [maps records arrays list map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put entries_by_pid 0 --kind hash'
            '  let entries = (0 | map-get entries_by_pid --kind hash)'
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
        name: "map-put-array-record-spread-string-field-get-tail-length"
        category: "maps"
        tags: [maps records arrays string list-spread map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put entries_by_pid 0 --kind hash'
            '  let entries = (0 | map-get entries_by_pid --kind hash)'
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
        name: "map-push-array-record-list-field-get-tail-element"
        category: "maps"
        tags: [maps records arrays queue list map-push map-pop get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-push entry_batches --kind queue'
            '  let entries = (map-pop entry_batches --kind queue)'
            '  if $entries {'
            '    let row = ($entries | get 1)'
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
        name: "map-push-array-record-spread-string-field-get-tail-length"
        category: "maps"
        tags: [maps records arrays queue string list-spread map-push map-pop get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-push entry_batches --kind queue'
            '  let entries = (map-pop entry_batches --kind queue)'
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
]
