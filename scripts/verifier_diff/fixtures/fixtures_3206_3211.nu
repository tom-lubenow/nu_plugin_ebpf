export const VERIFIER_DIFF_FIXTURES_3206_3211 = [
    {
        name: "global-define-type-array-string-first-str-length"
        category: "globals"
        tags: [globals arrays string first str length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | first | str length) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-last-is-empty"
        category: "globals"
        tags: [globals arrays string last is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | last | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-take-first-str-length"
        category: "globals"
        tags: [globals arrays string take first str length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | take 1 | first | str length) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-skip-first-is-empty"
        category: "globals"
        tags: [globals arrays string skip first is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | skip 1 | first | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-drop-last-length"
        category: "globals"
        tags: [globals arrays string drop last length global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | drop 1 | last | length) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-string-reverse-first-is-empty"
        category: "globals"
        tags: [globals arrays string reverse first is-empty global-define zero-fill accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (global-get names) | reverse | first | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
