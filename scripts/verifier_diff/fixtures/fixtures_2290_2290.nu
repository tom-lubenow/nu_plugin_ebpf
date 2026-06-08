const VERIFIER_DIFF_FIXTURES_2290_2290 = [
    {
        name: "global-typed-record-values-scalar-fields"
        category: "globals"
        tags: [globals records typed values get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let uid = (global-get seen_state | values | get 1)'
            '  $uid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
