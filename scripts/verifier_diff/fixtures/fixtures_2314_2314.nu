const VERIFIER_DIFF_FIXTURES_2314_2314 = [
    {
        name: "global-typed-array-get-out-of-bounds-rejects"
        category: "globals"
        tags: [globals arrays typed get reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-get ports | get 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "numeric get index 4 is out of bounds for typed array length 4"
    }
]
