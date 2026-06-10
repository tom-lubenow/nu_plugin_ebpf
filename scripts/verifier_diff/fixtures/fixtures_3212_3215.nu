export const VERIFIER_DIFF_FIXTURES_3212_3215 = [
    {
        name: "global-define-type-array-u32-append-length"
        category: "globals"
        tags: [globals arrays u32 append length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | append 7 | length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-append-last"
        category: "globals"
        tags: [globals arrays u32 append last global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | append 7 | last) == 7)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-prepend-length"
        category: "globals"
        tags: [globals arrays u32 prepend length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | prepend 7 | length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-prepend-first"
        category: "globals"
        tags: [globals arrays u32 prepend first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | prepend 7 | first) == 7)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
