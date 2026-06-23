const VERIFIER_DIFF_FIXTURES_2299_2299 = [
    {
        name: "global-typed-record-values-first-accepts-scalar-field"
        category: "globals"
        tags: [globals records typed values first scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:string:8}" seen_state'
            '  global-get seen_state | values | first | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
