export const VERIFIER_DIFF_FIXTURES_3247_3247 = [
    {
        name: "global-define-type-array-u32-bits-not-length"
        category: "globals"
        tags: [globals arrays u32 bits not length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | bits not --number-bytes 4 | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
