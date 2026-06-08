const VERIFIER_DIFF_FIXTURES_2300_2300 = [
    {
        name: "global-typed-record-select-missing-field-rejects"
        category: "globals"
        tags: [globals records typed select reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  global-get seen_state | select mem'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "select cannot find record field 'mem'"
    }
]
