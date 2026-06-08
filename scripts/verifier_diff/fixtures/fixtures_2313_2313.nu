const VERIFIER_DIFF_FIXTURES_2313_2313 = [
    {
        name: "global-typed-array-skip-drop-all-empty"
        category: "globals"
        tags: [globals arrays typed skip drop is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  let skipped_empty = (global-get ports | skip 4 | is-empty)'
            '  let dropped_empty = (global-get ports | drop 4 | is-empty)'
            '  $skipped_empty | count'
            '  $dropped_empty | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
