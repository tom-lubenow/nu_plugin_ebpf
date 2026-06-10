export const VERIFIER_DIFF_FIXTURES_3356_3357 = [
    {
        name: "global-define-type-array-string-str-replace-all-join-length"
        category: "globals"
        tags: [globals arrays string str replace all join length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa" "aba"] | global-define --type "array{string:8:2}" names'
            '  ((((global-get names) | str replace --all "a" "z" | str join ",") | str length) == 6)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-str-replace-variable-length-reject"
        category: "globals"
        tags: [globals arrays string str replace diagnostics global-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ["aa"] | global-define --type "array{string:8:1}" names'
            '  ((global-get names) | str replace "a" "zz" | str join "")'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "replacement length to equal find length"
    }
]
