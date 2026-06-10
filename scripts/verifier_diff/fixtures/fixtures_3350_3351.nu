export const VERIFIER_DIFF_FIXTURES_3350_3351 = [
    {
        name: "global-define-type-array-string-str-index-of-sum"
        category: "globals"
        tags: [globals arrays string str index-of math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["xa" "ba" "aa"] | global-define --type "array{string:8:3}" names'
            '  (((global-get names) | str index-of "a" | math sum) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-index-of-grapheme-rejects-runtime"
        category: "globals"
        tags: [globals arrays string str index-of grapheme-clusters diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | str index-of --grapheme-clusters "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str index-of --grapheme-clusters requires compile-time known string input"
    }
]
