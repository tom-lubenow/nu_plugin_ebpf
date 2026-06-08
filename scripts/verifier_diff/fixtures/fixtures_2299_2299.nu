const VERIFIER_DIFF_FIXTURES_2299_2299 = [
    {
        name: "global-typed-record-values-string-first-rejects"
        category: "globals"
        tags: [globals records typed values first string reject diagnostic]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:string:8}" seen_state'
            '  global-get seen_state | values | first | is-empty'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "values on typed record input currently supports only scalar output fields"
    }
]
