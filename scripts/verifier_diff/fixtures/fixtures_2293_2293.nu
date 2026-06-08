const VERIFIER_DIFF_FIXTURES_2293_2293 = [
    {
        name: "global-typed-record-merge-scalar-fields"
        category: "globals"
        tags: [globals records typed merge get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let merged_new_uid = (global-get seen_state | merge { tid: 7 } | get uid)'
            '  let merged_replace_cpu = (global-get seen_state | merge { uid: 7 } | get cpu)'
            '  $merged_new_uid | count'
            '  $merged_replace_cpu | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
