export const VERIFIER_DIFF_FIXTURES_3251_3251 = [
    {
        name: "global-define-type-array-i32-bits-numeric-length"
        category: "globals"
        tags: [globals arrays i32 bits and not shift rotate length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{i32:2}" nums'
            '  let nums = (global-get nums)'
            '  ((($nums | bits and 1 | length) == 2) and (($nums | bits not --number-bytes 4 | length) == 2) and (($nums | bits shl 1 --number-bytes 4 | length) == 2) and (($nums | bits ror 1 --number-bytes 4 | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
