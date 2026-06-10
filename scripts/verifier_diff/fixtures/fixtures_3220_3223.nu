export const VERIFIER_DIFF_FIXTURES_3220_3223 = [
    {
        name: "global-define-type-array-u32-sort-length"
        category: "globals"
        tags: [globals arrays u32 sort length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | sort | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-sort-first"
        category: "globals"
        tags: [globals arrays u32 sort first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | sort | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-sort-reverse-length"
        category: "globals"
        tags: [globals arrays u32 sort reverse length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | sort --reverse | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-sort-reverse-first"
        category: "globals"
        tags: [globals arrays u32 sort reverse first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | sort --reverse | first) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
