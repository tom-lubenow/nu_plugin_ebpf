export const VERIFIER_DIFF_FIXTURES_3260_3261 = [
    {
        name: "global-define-type-array-u64-where-length"
        category: "globals"
        tags: [globals arrays u64 where closure length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | where {|x| $x == 0 } | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u64-find-length"
        category: "globals"
        tags: [globals arrays u64 find length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | find 0 | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
