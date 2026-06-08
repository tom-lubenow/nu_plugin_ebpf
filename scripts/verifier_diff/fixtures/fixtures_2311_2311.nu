const VERIFIER_DIFF_FIXTURES_2311_2311 = [
    {
        name: "global-typed-array-take-zero-empty"
        category: "globals"
        tags: [globals arrays typed take is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  let empty = (global-get ports | take 0 | is-empty)'
            '  $empty | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
