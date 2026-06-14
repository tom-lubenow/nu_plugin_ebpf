export const VERIFIER_DIFF_FIXTURES_3733_3735 = [
    {
        name: "global-define-type-array-record-where-true-first"
        category: "globals"
        tags: [globals records arrays where closure first get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | global-define --type "array{record{pid:int,cpu:int}:2}" seen_entries'
            '  (((global-get seen_entries) | where {|row| true } | first).pid == 7)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-where-true-first"
        category: "globals"
        tags: [globals arrays string where closure first str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  ((((global-get names) | where {|x| true } | first) | str length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-record-list-field-where-true-first"
        category: "maps"
        tags: [maps map-define map-get arrays records list where closure first get length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define sample_states --kind array --value-type "array{record{samples:list:int:2}:2}" --max-entries 1'
            '  let entry = (0 | map-get sample_states --kind array)'
            '  if $entry {'
            '    (((($entry | where {|row| true } | first) | get samples) | length) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
