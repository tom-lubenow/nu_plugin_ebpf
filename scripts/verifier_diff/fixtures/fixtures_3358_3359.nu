export const VERIFIER_DIFF_FIXTURES_3358_3359 = [
    {
        name: "global-define-type-array-string-str-trim-right-char-length"
        category: "globals"
        tags: [globals arrays string str trim right char length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | str trim --right --char "x" | str length | first) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-trim-default-runtime-reject"
        category: "globals"
        tags: [globals arrays string str trim diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:1}" names'
            '  ((global-get names) | str trim | str join "")'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "currently requires --char"
    }
]
