const VERIFIER_DIFF_FIXTURES_2296_2296 = [
    {
        name: "global-typed-aggregate-describe-layouts"
        category: "globals"
        tags: [globals arrays records typed describe string metadata-only accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:4}" ports'
            '  global-define --type "array{record{pid:int,active:bool}:2}" states'
            '  let ports_desc = (global-get ports | describe | str starts-with "list<int>")'
            '  let states_desc = (global-get states | describe | str starts-with "list<record<pid: int, active: bool>>")'
            '  if $ports_desc and $states_desc { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
