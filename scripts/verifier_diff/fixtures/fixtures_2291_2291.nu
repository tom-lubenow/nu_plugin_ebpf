const VERIFIER_DIFF_FIXTURES_2291_2291 = [
    {
        name: "global-typed-record-insert-update-upsert-scalar-fields"
        category: "globals"
        tags: [globals records typed insert update upsert get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let inserted_uid = (global-get seen_state | insert tid 7 | get uid)'
            '  let updated_uid = (global-get seen_state | update uid 7 | get uid)'
            '  let upserted_uid = (global-get seen_state | upsert uid 9 | get uid)'
            '  $inserted_uid | count'
            '  $updated_uid | count'
            '  $upserted_uid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
