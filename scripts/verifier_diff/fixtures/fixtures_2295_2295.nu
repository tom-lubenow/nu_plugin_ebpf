const VERIFIER_DIFF_FIXTURES_2295_2295 = [
    {
        name: "global-typed-record-describe-fields"
        category: "globals"
        tags: [globals records typed describe string metadata-only accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:string:8,active:bool}" seen_state'
            '  let matches_layout = (global-get seen_state | describe | str starts-with "record<pid: int, comm: string, active: bool>")'
            '  if $matches_layout { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
