export const VERIFIER_DIFF_FIXTURES_3236_3237 = [
    {
        name: "global-define-type-array-u32-where-length"
        category: "globals"
        tags: [globals arrays u32 where closure length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | where {|x| $x == 0 } | length) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-where-initialized-length"
        category: "globals"
        tags: [globals arrays u32 where closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [3 4] | global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | where {|x| $x > 3 } | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-each-first"
        category: "globals"
        tags: [globals arrays u32 each closure first global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | each {|x| $x + 1 } | first) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-u32-each-initialized-first"
        category: "globals"
        tags: [globals arrays u32 each closure first global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [3 4] | global-define --type "array{u32:2}" ports'
            '  (((global-get ports) | each {|x| $x + 1 } | first) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-each-length"
        category: "globals"
        tags: [globals arrays string each closure str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  (((global-get names) | each {|x| $x | str length } | get 1) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-binary-each-length"
        category: "globals"
        tags: [globals arrays binary bytes each closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | each {|x| $x | bytes length } | get 1) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
