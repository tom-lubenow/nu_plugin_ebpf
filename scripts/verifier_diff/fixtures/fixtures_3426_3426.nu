export const VERIFIER_DIFF_FIXTURES_3426_3426 = [
    {
        name: "global-define-type-array-string-reverse-first-str-length"
        category: "globals"
        tags: [globals arrays string reverse first str length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  (((global-get names) | reverse | first | str length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
