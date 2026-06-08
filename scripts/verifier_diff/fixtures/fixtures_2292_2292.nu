const VERIFIER_DIFF_FIXTURES_2292_2292 = [
    {
        name: "global-typed-record-default-scalar-fields"
        category: "globals"
        tags: [globals records typed default get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let defaulted_tid = (global-get seen_state | default 7 tid | get tid)'
            '  let preserved_uid = (global-get seen_state | default 7 uid | get uid)'
            '  $defaulted_tid | count'
            '  $preserved_uid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
