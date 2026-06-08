const VERIFIER_DIFF_FIXTURES_2297_2297 = [
    {
        name: "global-typed-record-columns-field-names"
        category: "globals"
        tags: [globals records typed columns str join metadata-only accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:string:8,active:bool}" seen_state'
            '  let fields = (global-get seen_state | columns | str join ",")'
            '  if ($fields | str starts-with "pid,comm,active") { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
