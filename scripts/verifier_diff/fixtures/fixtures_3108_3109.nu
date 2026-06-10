const VERIFIER_DIFF_FIXTURES_3108_3109 = [
    {
        name: "global-define-rejects-invalid-string-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type string:abc bad'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'string:abc' has an invalid string capacity"
    }
    {
        name: "global-define-rejects-invalid-numeric-list-capacity"
        category: "globals"
        tags: [globals global-define diagnostics reject capacity list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  global-define --type list:int:abc bad'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global type spec 'list:int:abc' has an invalid list capacity"
    }
]
