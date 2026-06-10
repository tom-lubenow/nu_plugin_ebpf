export const VERIFIER_DIFF_FIXTURES_3232_3233 = [
    {
        name: "global-define-type-array-u32-find-length"
        category: "globals"
        tags: [globals arrays u32 find length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | find 0 | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-compact-length"
        category: "globals"
        tags: [globals arrays u32 compact length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | compact | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
