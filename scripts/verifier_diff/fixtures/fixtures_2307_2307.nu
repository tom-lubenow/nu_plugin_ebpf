const VERIFIER_DIFF_FIXTURES_2307_2307 = [
    {
        name: "global-typed-record-merge-added-and-replaced-fields"
        category: "globals"
        tags: [globals records typed merge get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let merged_tid = (global-get seen_state | merge { tid: 7 uid: 9 } | get tid)'
            '  let merged_uid = (global-get seen_state | merge { tid: 7 uid: 9 } | get uid)'
            '  $merged_tid | count'
            '  $merged_uid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
