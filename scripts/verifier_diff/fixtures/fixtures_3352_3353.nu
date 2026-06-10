export const VERIFIER_DIFF_FIXTURES_3352_3353 = [
    {
        name: "global-define-type-array-string-str-index-of-end-sum"
        category: "globals"
        tags: [globals arrays string str index-of end math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aba" "ba" "aa"] | global-define --type "array{string:8:3}" names'
            '  (((global-get names) | str index-of --end "a" | math sum) == 4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-index-of-range-sum"
        category: "globals"
        tags: [globals arrays string str index-of range math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["xa" "ba" "aa"] | global-define --type "array{string:8:3}" names'
            '  (((global-get names) | str index-of --range 1..2 "a" | math sum) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
