export const VERIFIER_DIFF_FIXTURES_3374_3375 = [
    {
        name: "global-define-type-array-string-str-trim-left-char-join"
        category: "globals"
        tags: [globals arrays string str trim left char join global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["xxaa" "xbb"] | global-define --type "array{string:8:2}" names'
            '  ((global-get names) | str trim --left --char "x" | str join "-" | str starts-with "aa-bb")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-trim-char-both-reject"
        category: "globals"
        tags: [globals arrays string str trim char diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["xx"] | global-define --type "array{string:8:1}" names'
            '  ((global-get names) | str trim --char "x" | str join "")'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "currently supports only --left --char or --right --char"
    }
]
