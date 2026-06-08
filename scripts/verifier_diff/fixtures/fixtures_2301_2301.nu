const VERIFIER_DIFF_FIXTURES_2301_2301 = [
    {
        name: "global-typed-record-rename-column-missing-rejects"
        category: "globals"
        tags: [globals records typed rename column reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  global-get seen_state | rename --column { mem: rss }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "rename --column cannot find record field 'mem'"
    }
]
