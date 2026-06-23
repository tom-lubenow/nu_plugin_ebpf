export const VERIFIER_DIFF_FIXTURES_3425_3425 = [
    {
        name: "global-define-type-array-string-str-length-grapheme-zero-fill-sum"
        category: "globals"
        tags: [globals arrays string str length grapheme-clusters math sum global-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  global-define --type "array{string:8:2}" names'
            '  (((global-get names) | str length --grapheme-clusters | math sum) == 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
