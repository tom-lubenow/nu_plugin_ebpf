const VERIFIER_DIFF_FIXTURES_2304_2304 = [
    {
        name: "global-typed-record-get-missing-field-rejects"
        category: "globals"
        tags: [globals records typed get field-path reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  global-get seen_state | get "mem"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "typed field path 'mem' has no field 'mem'"
    }
]
