const VERIFIER_DIFF_FIXTURES_2286_2286 = [
    {
        name: "global-typed-record-metadata-shape-ops"
        category: "globals"
        tags: [globals records typed columns values length is-not-empty metadata-only accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "record{pid:int,comm:string:8}" seen_state'
            '  let cols_len = ((global-get seen_state | columns | length) == 2)'
            '  let vals_len = ((global-get seen_state | values | length) == 2)'
            '  let vals_non_empty = (global-get seen_state | values | is-not-empty)'
            '  if $cols_len and ($vals_len and $vals_non_empty) { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
