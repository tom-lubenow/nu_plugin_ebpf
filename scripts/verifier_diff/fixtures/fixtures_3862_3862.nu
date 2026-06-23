export const VERIFIER_DIFF_FIXTURES_3862_3862 = [
    {
        name: "global-define-type-array-u64-where-not-one-first-accepts-zero-fill"
        category: "globals"
        tags: [globals arrays u64 where closure first zero-fill comparison accept global-define]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | where {|x| $x != 1 } | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
