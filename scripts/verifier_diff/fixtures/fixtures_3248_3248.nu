export const VERIFIER_DIFF_FIXTURES_3248_3248 = [
    {
        name: "global-define-type-array-u32-bits-shift-length"
        category: "globals"
        tags: [globals arrays u32 bits shift length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  let ports = (global-get ports)'
            '  ((($ports | bits shl 1 --number-bytes 4 | length) == 2) and (($ports | bits shr 1 --number-bytes 4 | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
