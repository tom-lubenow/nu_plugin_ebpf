export const VERIFIER_DIFF_FIXTURES_3348_3349 = [
    {
        name: "global-define-type-array-string-str-contains-sum"
        category: "globals"
        tags: [globals arrays string str contains math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bb" "ca"] | global-define --type "array{string:8:3}" names'
            '  (((global-get names) | str contains "a" | math sum) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-contains-ignore-case-rejects-runtime"
        category: "globals"
        tags: [globals arrays string str contains ignore-case diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | str contains --ignore-case "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains --ignore-case requires compile-time known string input"
    }
]
