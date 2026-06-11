export const VERIFIER_DIFF_FIXTURES_3475_3476 = [
    {
        name: "map-define-array-list-key-put-get"
        category: "maps"
        tags: [maps map-define global-define arrays list key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_sets --kind hash --key-type "array{list:int:2:2}" --value-type int'
            '  [[1] [2 3]] | global-define --type "array{list:int:2:2}" key_sets'
            '  let key = (global-get key_sets)'
            '  42 | map-put keyed_sets $key --kind hash'
            '  let entry = ($key | map-get keyed_sets --kind hash)'
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
        name: "map-define-record-array-list-field-key-put-get"
        category: "maps"
        tags: [maps map-define global-define records arrays list key map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_state --kind hash --key-type "record{sets:array{list:int:2:2},pid:int}" --value-type int'
            '  { sets: [[1] [2 3]] pid: 7 } | global-define --type "record{sets:array{list:int:2:2},pid:int}" key_state'
            '  let key = (global-get key_state)'
            '  42 | map-put keyed_state $key --kind hash'
            '  let entry = ($key | map-get keyed_state --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
