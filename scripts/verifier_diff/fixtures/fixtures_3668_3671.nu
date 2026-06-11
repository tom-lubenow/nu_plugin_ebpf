export const VERIFIER_DIFF_FIXTURES_3668_3671 = [
    {
        name: "map-peek-queue-array-record-list-field-get-tail-element"
        category: "maps"
        tags: [maps queue records arrays list map-push map-peek get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-push peek_entry_batches --kind queue'
            '  let entries = (map-peek peek_entry_batches --kind queue)'
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
        name: "map-peek-queue-array-record-string-builder-tail-length"
        category: "maps"
        tags: [maps queue records arrays string append map-push map-peek get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-push peek_name_batches --kind queue'
            '  let stored = (map-peek peek_name_batches --kind queue)'
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
        name: "map-peek-stack-array-record-list-builder-tail-element"
        category: "maps"
        tags: [maps stack records arrays list append map-push map-peek get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-push peek_stack_entry_batches --kind stack'
            '  let stored = (map-peek peek_stack_entry_batches --kind stack)'
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
        name: "map-peek-stack-array-record-spread-string-tail-length"
        category: "maps"
        tags: [maps stack records arrays string list-spread map-push map-peek get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-push peek_stack_name_batches --kind stack'
            '  let stored = (map-peek peek_stack_name_batches --kind stack)'
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
