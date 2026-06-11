export const VERIFIER_DIFF_FIXTURES_3672_3675 = [
    {
        name: "map-define-queue-array-record-list-value-type-pop-tail-element"
        category: "maps"
        tags: [maps queue map-define records arrays list value-type map-push map-pop get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_queue_batches --kind queue --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 4'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-push typed_queue_batches --kind queue'
            '  let entries = (map-pop typed_queue_batches --kind queue)'
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
        name: "map-define-queue-array-record-string-value-type-peek-tail-length"
        category: "maps"
        tags: [maps queue map-define records arrays string append value-type map-push map-peek get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_queue_names --kind queue --value-type "array{record{id:int,name:string:15}:2}" --max-entries 4'
            '  let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '  $entries | map-push typed_queue_names --kind queue'
            '  let stored = (map-peek typed_queue_names --kind queue)'
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
        name: "map-define-stack-array-record-list-value-type-pop-tail-element"
        category: "maps"
        tags: [maps stack map-define records arrays list append value-type map-push map-pop get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_stack_batches --kind stack --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 4'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-push typed_stack_batches --kind stack'
            '  let stored = (map-pop typed_stack_batches --kind stack)'
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
        name: "map-define-stack-array-record-string-value-type-peek-tail-length"
        category: "maps"
        tags: [maps stack map-define records arrays string list-spread value-type map-push map-peek get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define typed_stack_names --kind stack --value-type "array{record{id:int,name:string:15}:2}" --max-entries 4'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-push typed_stack_names --kind stack'
            '  let stored = (map-peek typed_stack_names --kind stack)'
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
