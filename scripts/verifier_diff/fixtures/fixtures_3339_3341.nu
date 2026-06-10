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
        name: "global-define-type-array-string-str-join-wide-element"
        category: "globals"
        tags: [globals arrays string str join length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] | global-define --type "array{string:65:1}" names'
            '  (((global-get names) | str join | str length) == 65)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
