export const VERIFIER_DIFF_FIXTURES_3354_3355 = [
    {
        name: "global-define-type-array-string-str-substring-range-join-length"
        category: "globals"
        tags: [globals arrays string str substring range join length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["abcd" "xy" "a"] | global-define --type "array{string:8:3}" names'
            '  ((((global-get names) | str substring 1..2 | str join ",") | str length) == 5)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-substring-negative-range-reject"
        category: "globals"
        tags: [globals arrays string str substring range diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["abcd"] | global-define --type "array{string:8:1}" names'
            '  ((global-get names) | str substring 1..-1 | str join "")'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "supports only non-negative byte range ends"
    }
]
