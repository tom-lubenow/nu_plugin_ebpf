export const VERIFIER_DIFF_FIXTURES_3250_3250 = [
    {
        name: "global-define-type-array-u32-math-integer-identity-length"
        category: "globals"
        tags: [globals arrays u32 math ceil floor round length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  let ports = (global-get ports)'
            '  ((($ports | math ceil | length) == 2) and (($ports | math floor | length) == 2) and (($ports | math round | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
