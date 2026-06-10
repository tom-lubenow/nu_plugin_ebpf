export const VERIFIER_DIFF_FIXTURES_3342_3343 = [
    {
        name: "global-define-type-array-string-str-length-sum"
        category: "globals"
        tags: [globals arrays string str length math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bbb"] | global-define --type "array{string:8:2}" names'
            '  (((global-get names) | str length | math sum) == 5)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-length-chars-rejects-runtime"
        category: "globals"
        tags: [globals arrays string str length chars diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | str length --chars'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length requires compile-time known string input"
    }
]
