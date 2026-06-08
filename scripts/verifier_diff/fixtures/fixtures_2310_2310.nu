const VERIFIER_DIFF_FIXTURES_2310_2310 = [
    {
        name: "global-typed-record-select-then-reject-empty"
        category: "globals"
        tags: [globals records typed select reject is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  let empty = (global-get seen_state | select pid | reject pid | is-empty)'
            '  $empty | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
