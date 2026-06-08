const VERIFIER_DIFF_FIXTURES_2302_2302 = [
    {
        name: "global-typed-record-update-missing-field-rejects"
        category: "globals"
        tags: [globals records typed update reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  global-get seen_state | update mem 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "update cannot find record field 'mem'"
    }
]
