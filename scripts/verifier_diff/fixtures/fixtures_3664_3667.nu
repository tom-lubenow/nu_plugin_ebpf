export const VERIFIER_DIFF_FIXTURES_3664_3667 = [
    {
        name: "array-of-maps-dynamic-inner-array-record-list-value-put-get-tail-element"
        category: "maps"
        tags: [maps map-in-map array-of-maps dynamic-update dynamic-lookup records arrays list value-type map-put map-get get accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_sample_batches --kind hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 16'
            '  map-define outer_sample_batches --kind array-of-maps --inner-map inner_sample_batches --max-entries 4'
            '  let inner = (0 | map-get outer_sample_batches)'
            '  if $inner {'
            '    [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | map-put $inner 7'
            '    let stored = (7 | map-get $inner)'
            '    if $stored {'
            '      let row = ($stored | get 1)'
            '      return (($row.id == 2) and (($row.samples | get 1) == 4))'
            '    }'
            '  }'
            '  false'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "array-of-maps-dynamic-inner-array-record-string-builder-value-put-get-tail-length"
        category: "maps"
        tags: [maps map-in-map array-of-maps dynamic-update dynamic-lookup records arrays string append value-type map-put map-get get str length accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_name_batches --kind hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}" --max-entries 16'
            '  map-define outer_name_batches --kind array-of-maps --inner-map inner_name_batches --max-entries 4'
            '  let inner = (0 | map-get outer_name_batches)'
            '  if $inner {'
            '    let entries = ([] | append { id: 1 name: "aa" } | append { id: 2 name: "bbb" })'
            '    $entries | map-put $inner 7'
            '    let stored = (7 | map-get $inner)'
            '    if $stored {'
            '      let row = ($stored | get 1)'
            '      return (($row.id == 2) and (($row.name | str length) == 3))'
            '    }'
            '  }'
            '  false'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "hash-of-maps-dynamic-inner-array-record-list-builder-value-contains-delete"
        category: "maps"
        tags: [maps map-in-map hash-of-maps dynamic-update dynamic-lookup dynamic-delete records arrays list append value-type map-put map-contains map-delete accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_hash_sample_batches --kind hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}" --max-entries 16'
            '  map-define outer_hash_sample_batches --kind hash-of-maps --key-type u32 --inner-map inner_hash_sample_batches --max-entries 4'
            '  let inner = (1 | map-get outer_hash_sample_batches)'
            '  if $inner {'
            '    let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '    $entries | map-put $inner 7'
            '    let present = (7 | map-contains $inner)'
            '    7 | map-delete $inner'
            '    return $present'
            '  }'
            '  false'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "hash-of-maps-dynamic-inner-array-record-string-spread-value-put-delete"
        category: "maps"
        tags: [maps map-in-map hash-of-maps dynamic-update dynamic-delete records arrays string list-spread value-type map-put map-delete accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_hash_name_batches --kind hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}" --max-entries 16'
            '  map-define outer_hash_name_batches --kind hash-of-maps --key-type u32 --inner-map inner_hash_name_batches --max-entries 4'
            '  let inner = (1 | map-get outer_hash_name_batches)'
            '  if $inner {'
            '    let tail = [{ id: 2 name: "bbb" }]'
            '    [{ id: 1 name: "aa" }, ...$tail] | map-put $inner 7'
            '    7 | map-delete $inner'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
