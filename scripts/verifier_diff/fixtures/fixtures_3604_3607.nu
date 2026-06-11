export const VERIFIER_DIFF_FIXTURES_3604_3607 = [
    {
        name: "map-define-array-record-list-field-key-put-get"
        category: "maps"
        tags: [maps map-define global-define records arrays list key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches --kind hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" key_entries'
            '  let key = (global-get key_entries)'
            '  42 | map-put keyed_batches $key --kind hash'
            '  let entry = ($key | map-get keyed_batches --kind hash)'
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
        name: "map-define-array-record-string-field-key-put-get"
        category: "maps"
        tags: [maps map-define global-define records arrays string key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_names --kind hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" key_entries'
            '  let key = (global-get key_entries)'
            '  42 | map-put keyed_names $key --kind hash'
            '  let entry = ($key | map-get keyed_names --kind hash)'
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
        name: "map-define-array-record-list-field-key-contains-delete"
        category: "maps"
        tags: [maps map-define global-define records arrays list key map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_batches_ops --kind hash --key-type "array{record{id:int,samples:list:int:2}:2}" --value-type int'
            '  [{ id: 1 samples: [1 2] } { id: 2 samples: [3 4] }] | global-define --type "array{record{id:int,samples:list:int:2}:2}" key_entries'
            '  let key = (global-get key_entries)'
            '  42 | map-put keyed_batches_ops $key --kind hash'
            '  if (map-contains keyed_batches_ops $key --kind hash) {'
            '    map-delete keyed_batches_ops $key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-array-record-string-field-key-contains-delete"
        category: "maps"
        tags: [maps map-define global-define records arrays string key map-contains map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_names_ops --kind hash --key-type "array{record{id:int,name:string:15}:2}" --value-type int'
            '  [{ id: 1 name: "aa" } { id: 2 name: "bbb" }] | global-define --type "array{record{id:int,name:string:15}:2}" key_entries'
            '  let key = (global-get key_entries)'
            '  42 | map-put keyed_names_ops $key --kind hash'
            '  if (map-contains keyed_names_ops $key --kind hash) {'
            '    map-delete keyed_names_ops $key --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
