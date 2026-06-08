const VERIFIER_DIFF_FIXTURES_2298_2298 = [
    {
        name: "global-typed-record-values-scalar-get"
        category: "globals"
        tags: [globals records typed values get scalar list accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let vals = (global-get seen_state | values)'
            '  let len_ok = (($vals | length) == 3)'
            '  let uid_ok = (($vals | get 1) == 0)'
            '  if $len_ok and $uid_ok { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
