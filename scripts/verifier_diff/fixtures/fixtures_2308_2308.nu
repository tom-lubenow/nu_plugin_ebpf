const VERIFIER_DIFF_FIXTURES_2308_2308 = [
    {
        name: "global-typed-record-reject-missing-field-rejects"
        category: "globals"
        tags: [globals records typed reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  global-get seen_state | reject mem'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reject cannot find record field 'mem'"
    }
]
