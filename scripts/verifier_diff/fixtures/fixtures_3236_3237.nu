export const VERIFIER_DIFF_FIXTURES_3236_3237 = [
    {
        name: "global-define-type-array-u32-where-length"
        category: "globals"
        tags: [globals arrays u32 where closure length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | where {|x| $x == 0 } | length) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-each-first"
        category: "globals"
        tags: [globals arrays u32 each closure first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | each {|x| $x + 1 } | first) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
