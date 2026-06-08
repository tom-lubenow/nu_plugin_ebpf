const VERIFIER_DIFF_FIXTURES_2287_2287 = [
    {
        name: "global-typed-record-command-get-field"
        category: "globals"
        tags: [globals records typed get field-path accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  let pid = (global-get seen_state | get "pid")'
            '  $pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
