const VERIFIER_DIFF_FIXTURES_2312_2312 = [
    {
        name: "global-typed-array-first-last-zero-empty"
        category: "globals"
        tags: [globals arrays typed first last is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  let first_empty = (global-get ports | first 0 | is-empty)'
            '  let last_empty = (global-get ports | last 0 | is-empty)'
            '  $first_empty | count'
            '  $last_empty | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
