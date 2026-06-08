const VERIFIER_DIFF_FIXTURES_2303_2303 = [
    {
        name: "global-typed-record-insert-existing-field-rejects"
        category: "globals"
        tags: [globals records typed insert reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  global-get seen_state | insert pid 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "insert cannot replace existing record field 'pid'"
    }
]
