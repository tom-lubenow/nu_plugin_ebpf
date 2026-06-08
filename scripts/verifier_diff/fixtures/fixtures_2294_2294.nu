const VERIFIER_DIFF_FIXTURES_2294_2294 = [
    {
        name: "global-typed-record-shape-consumers"
        category: "globals"
        tags: [globals records typed length is-empty is-not-empty scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  let field_count = (global-get seen_state | length)'
            '  let empty = (global-get seen_state | is-empty)'
            '  let non_empty = (global-get seen_state | is-not-empty)'
            '  $field_count | count'
            '  $empty | count'
            '  $non_empty | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
