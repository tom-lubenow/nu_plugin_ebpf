export const VERIFIER_DIFF_FIXTURES_3754_3756 = [
    {
        name: "map-get-array-u64-where-length"
        category: "maps"
        tags: [maps map-define map-get arrays u64 where closure length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define wide_ports --kind array --value-type "array{u64:2}" --max-entries 1'
            '  let entry = (0 | map-get wide_ports --kind array)'
            '  if $entry {'
            '    ((($entry | where {|x| $x == 0 } | length) == 2))'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-where-true-first"
        category: "globals"
        tags: [globals arrays u64 where closure first global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | where {|x| true } | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-where-zero-first-accepts-zero-fill"
        category: "globals"
        tags: [globals arrays u64 where closure first zero-fill accept global-define]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | where {|x| $x == 0 } | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
