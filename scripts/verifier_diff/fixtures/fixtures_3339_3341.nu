export const VERIFIER_DIFF_FIXTURES_3339_3341 = [
    {
        name: "global-define-type-array-string-str-join-initialized"
        category: "globals"
        tags: [globals arrays string str join global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "bb"] | global-define --type "array{string:8:2}" names'
            '  ((global-get names) | str join "-" | str starts-with "aa-bb")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-join-zeroed"
        category: "globals"
        tags: [globals arrays string str join length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | str join "-" | str length) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-join-rejects-wide-element"
        category: "globals"
        tags: [globals arrays string str join diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:65:1}" names'
            '  (global-get names) | str join'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str join on typed fixed string arrays supports string elements up to 64 bytes"
    }
]
