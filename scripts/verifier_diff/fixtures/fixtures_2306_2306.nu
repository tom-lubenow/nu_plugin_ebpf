const VERIFIER_DIFF_FIXTURES_2306_2306 = [
    {
        name: "global-typed-record-rename-block-fields"
        category: "globals"
        tags: [globals records typed rename block get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32}" seen_state'
            '  let pid = (global-get seen_state | rename --block { str upcase } | get PID)'
            '  $pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
