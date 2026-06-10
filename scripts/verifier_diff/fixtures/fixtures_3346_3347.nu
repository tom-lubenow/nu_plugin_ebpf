export const VERIFIER_DIFF_FIXTURES_3346_3347 = [
    {
        name: "global-define-type-array-string-str-ends-with-sum"
        category: "globals"
        tags: [globals arrays string str ends-with math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "ba" "bb"] | global-define --type "array{string:8:3}" names'
            '  (((global-get names) | str ends-with "a" | math sum) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-ends-with-ignore-case-rejects-runtime"
        category: "globals"
        tags: [globals arrays string str ends-with ignore-case diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | str ends-with --ignore-case "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with --ignore-case requires compile-time known string input"
    }
]
