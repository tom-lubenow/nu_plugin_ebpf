export const VERIFIER_DIFF_FIXTURES_3720_3722 = [
    {
        name: "global-define-type-array-string-where-length"
        category: "globals"
        tags: [globals arrays string where closure str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  (((global-get names) | where {|x| ($x | str length) == 3 } | length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-bytes-where-length"
        category: "globals"
        tags: [globals arrays binary bytes where closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | global-define --type "array{bytes:4:2}" buffers'
            '  (((global-get buffers) | where {|x| ($x | bytes length) == 4 } | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-where-first"
        category: "globals"
        tags: [globals arrays string where closure first str length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  ((((global-get names) | where {|x| ($x | str length) == 3 } | first) | str length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
