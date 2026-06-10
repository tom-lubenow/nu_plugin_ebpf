export const VERIFIER_DIFF_FIXTURES_3344_3345 = [
    {
        name: "global-define-type-array-string-str-starts-with-sum"
        category: "globals"
        tags: [globals arrays string str starts-with math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "ab" "ba"] | global-define --type "array{string:8:3}" names'
            '  (((global-get names) | str starts-with "a" | math sum) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-starts-with-ignore-case-rejects-runtime"
        category: "globals"
        tags: [globals arrays string str starts-with ignore-case diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | str starts-with --ignore-case "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with --ignore-case requires compile-time known string input"
    }
]
