export const VERIFIER_DIFF_FIXTURES_3780_3781 = [
    {
        name: "global-define-type-array-record-string-field-each-str-length-chars-sum"
        category: "globals"
        tags: [globals arrays records string each closure str length chars math sum global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{name: "é"} {name: "字"}] | global-define --type "array{record{name:string:8}:2}" names'
            '  (((global-get names) | each {|row| ($row.name | str length --chars) } | math sum) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-record-string-field-where-str-length-chars"
        category: "globals"
        tags: [globals arrays records string where closure str length chars global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{name: "é"} {name: "字"}] | global-define --type "array{record{name:string:8}:2}" names'
            '  (((global-get names) | where {|row| ($row.name | str length --chars) == 1 } | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
