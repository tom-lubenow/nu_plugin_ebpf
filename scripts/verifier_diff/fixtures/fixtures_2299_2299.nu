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
    {
        name: "global-typed-record-values-drop-projects-string-field"
        category: "globals"
        tags: [globals records typed values drop first get string accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:string:8}" seen_state'
            '  let first_len = (global-get seen_state | values | drop 1 | first | str length --utf-8-bytes)'
            '  let get_len = (global-get seen_state | values | drop 1 | get 0 | str length --utf-8-bytes)'
            '  ($first_len == 0) and ($get_len == 0)'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
]
