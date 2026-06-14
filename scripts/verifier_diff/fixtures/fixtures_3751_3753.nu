export const VERIFIER_DIFF_FIXTURES_3751_3753 = [
    {
        name: "global-define-type-array-u64-each-bool-all"
        category: "globals"
        tags: [globals arrays u64 each closure all bool global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  ((global-get ports) | each {|x| $x == 0 } | all {|flag| $flag })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u64-each-bool-all"
        category: "maps"
        tags: [maps map-define map-get arrays u64 each closure all bool accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    (($entry | each {|x| $x == 0 } | all {|flag| $flag }))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-each-identity-rejects"
        category: "globals"
        tags: [globals arrays u64 each closure diagnostics reject global-define]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | each {|x| $x } | length) == 2)'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "each on typed fixed arrays with u64 elements requires the closure to return a bool, signed integer, or <=32-bit unsigned integer value"
    }
]
