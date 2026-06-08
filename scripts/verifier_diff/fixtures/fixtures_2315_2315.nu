const VERIFIER_DIFF_FIXTURES_2315_2315 = [
    {
        name: "global-typed-array-get-negative-index-rejects"
        category: "globals"
        tags: [globals arrays typed get reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  let i = -1'
            '  global-get ports | get $i'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "numeric get index must be non-negative for typed array input"
    }
]
