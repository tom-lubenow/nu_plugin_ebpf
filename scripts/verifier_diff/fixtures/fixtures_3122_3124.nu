const VERIFIER_DIFF_FIXTURES_3122_3124 = [
    {
        name: "global-define-rejects-list-incompatible-value-semantics"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer list semantics]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | global-define --type list:int:4 values'
            '  [1 2 3] | global-define --type list:int:4 values'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global 'values' is used with incompatible value semantics"
    }
    {
        name: "global-define-rejects-record-list-field-incompatible-value-semantics"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer record list semantics]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {samples: [1 2]} | global-define --type "record{samples:list:int:4}" state'
            '  {samples: [1 2 3]} | global-define --type "record{samples:list:int:4}" state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global 'state' is used with incompatible value semantics"
    }
    {
        name: "global-define-rejects-fixed-array-list-incompatible-value-semantics"
        category: "globals"
        tags: [globals global-define diagnostics reject initializer array list semantics]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [[1] [2]] | global-define --type "array{list:int:4:2}" samples'
            '  [[1 2] [3 4]] | global-define --type "array{list:int:4:2}" samples'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global 'samples' is used with incompatible value semantics"
    }
]
