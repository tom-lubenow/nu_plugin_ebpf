const VERIFIER_DIFF_FIXTURES_2309_2309 = [
    {
        name: "global-typed-record-reject-all-fields-empty"
        category: "globals"
        tags: [globals records typed reject is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  let empty = (global-get seen_state | reject pid uid | is-empty)'
            '  $empty | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
