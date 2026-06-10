export const VERIFIER_DIFF_FIXTURES_3246_3246 = [
    {
        name: "global-define-type-array-u32-bits-and-length"
        category: "globals"
        tags: [globals arrays u32 bits and length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | bits and 1 | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
