const VERIFIER_DIFF_FIXTURES_2321_2321 = [
    {
        name: "global-typed-array-length-empty-predicates"
        category: "globals"
        tags: [globals arrays typed length is-empty is-not-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  let ports = (global-get ports)'
            '  let len = ($ports | length)'
            '  let empty = ($ports | is-empty)'
            '  let nonempty = ($ports | is-not-empty)'
            '  if ($len == 4) and ($empty == false) and $nonempty { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
