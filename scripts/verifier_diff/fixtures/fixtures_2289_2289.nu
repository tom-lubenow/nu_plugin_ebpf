const VERIFIER_DIFF_FIXTURES_2289_2289 = [
    {
        name: "global-typed-record-rename-scalar-fields"
        category: "globals"
        tags: [globals records typed rename get scalar accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,uid:u32,cpu:u32}" seen_state'
            '  let positional_uid = (global-get seen_state | rename tid user core | get user)'
            '  let mapped_uid = (global-get seen_state | rename --column { uid: user } | get user)'
            '  $positional_uid | count'
            '  $mapped_uid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
