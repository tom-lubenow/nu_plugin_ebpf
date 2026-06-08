const VERIFIER_DIFF_FIXTURES_2288_2288 = [
    {
        name: "global-typed-record-select-reject-scalar-fields"
        category: "globals"
        tags: [globals records typed select reject get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,comm:string:8}" seen_state'
            '  let selected_uid = (global-get seen_state | select pid uid | get uid)'
            '  let rejected_uid = (global-get seen_state | reject comm | get uid)'
            '  $selected_uid | count'
            '  $rejected_uid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
