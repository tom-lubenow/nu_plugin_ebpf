const VERIFIER_DIFF_FIXTURES_2305_2305 = [
    {
        name: "global-typed-record-upsert-missing-field"
        category: "globals"
        tags: [globals records typed upsert get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  let tid = (global-get seen_state | upsert tid 7 | get tid)'
            '  $tid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
