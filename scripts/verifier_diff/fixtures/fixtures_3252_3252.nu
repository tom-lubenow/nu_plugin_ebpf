export const VERIFIER_DIFF_FIXTURES_3252_3252 = [
    {
        name: "global-define-type-array-u64-compact-length"
        category: "globals"
        tags: [globals arrays u64 compact length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u64:2}" ports'
            '  (((global-get ports) | compact | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
