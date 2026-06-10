export const VERIFIER_DIFF_FIXTURES_3249_3249 = [
    {
        name: "global-define-type-array-u32-bits-rotate-length"
        category: "globals"
        tags: [globals arrays u32 bits rotate length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  let ports = (global-get ports)'
            '  ((($ports | bits rol 1 --number-bytes 4 | length) == 2) and (($ports | bits ror 1 --number-bytes 4 | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
