export const VERIFIER_DIFF_FIXTURES_3245_3245 = [
    {
        name: "global-define-type-array-u32-reverse-length"
        category: "globals"
        tags: [globals arrays u32 reverse length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | reverse | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
