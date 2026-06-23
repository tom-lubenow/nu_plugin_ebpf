export const VERIFIER_DIFF_FIXTURES_3863_3863 = [
    {
        name: "global-define-type-array-u64-each-identity-first-accepts-zero-fill"
        category: "globals"
        tags: [globals arrays u64 each closure identity first zero-fill accept global-define]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | each {|x| $x } | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
