export const VERIFIER_DIFF_FIXTURES_3684_3687 = [
    {
        name: "map-define-per-cpu-hash-array-record-list-builder-value-put-get-tail-element"
        category: "maps"
        tags: [maps per-cpu-hash map-define records arrays list append value-type map-put map-get get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_sample_batches_build --kind per-cpu-hash --key-type u32 --value-type "array{record{id:int,samples:list:int:2}:2}"'
            '  let entries = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  $entries | map-put cpu_sample_batches_build 0 --kind per-cpu-hash'
            '  let stored = (0 | map-get cpu_sample_batches_build --kind per-cpu-hash)'
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
        name: "map-define-per-cpu-hash-array-record-string-spread-value-put-get-tail-length"
        category: "maps"
        tags: [maps per-cpu-hash map-define records arrays string list-spread value-type map-put map-get get str length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_name_batches_spread --kind per-cpu-hash --key-type u32 --value-type "array{record{id:int,name:string:15}:2}"'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  [{ id: 1 name: "aa" }, ...$tail] | map-put cpu_name_batches_spread 0 --kind per-cpu-hash'
            '  let stored = (0 | map-get cpu_name_batches_spread --kind per-cpu-hash)'
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
        name: "map-define-per-cpu-hash-array-record-list-builder-source-key-contains"
        category: "maps"
        tags: [maps per-cpu-hash map-define records arrays list append key-type source-key map-put map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_source_keyed_batches --kind per-cpu-hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  let key = ([] | append { id: 1 samples: [1 2] } | append { id: 2 samples: [3 4] })'
            '  42 | map-put cpu_source_keyed_batches $key --kind per-cpu-hash'
            '  map-contains cpu_source_keyed_batches $key --kind per-cpu-hash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-per-cpu-hash-array-record-string-spread-source-key-put"
        category: "maps"
        tags: [maps per-cpu-hash map-define records arrays string list-spread key-type source-key map-put accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define cpu_source_keyed_names_spread --kind per-cpu-hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  let tail = [{ id: 2 name: "bbb" }]'
            '  let key = [{ id: 1 name: "aa" }, ...$tail]'
            '  42 | map-put cpu_source_keyed_names_spread $key --kind per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
