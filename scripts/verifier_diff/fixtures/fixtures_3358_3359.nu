export const VERIFIER_DIFF_FIXTURES_3358_3359 = [
    {
        name: "global-define-type-string-str-trim-char-length"
        category: "globals"
        tags: [globals string str trim char length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "string:8" name'
            '  (((global-get name) | str trim --char "x" | str length) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
        name: "global-define-type-array-string-str-trim-default-runtime-length"
        category: "globals"
        tags: [globals arrays string str trim default length global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:1}" names'
            '  (((global-get names) | str trim | str length | first) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
