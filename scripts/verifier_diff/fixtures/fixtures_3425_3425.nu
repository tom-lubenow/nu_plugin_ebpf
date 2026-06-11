export const VERIFIER_DIFF_FIXTURES_3425_3425 = [
    {
        name: "global-define-type-array-string-str-length-grapheme-rejects-runtime"
        category: "globals"
        tags: [globals arrays string str length grapheme-clusters diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | str length --grapheme-clusters'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length requires compile-time known string input"
    }
]
