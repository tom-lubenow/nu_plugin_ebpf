export const VERIFIER_DIFF_FIXTURES_3727_3729 = [
    {
        name: "global-define-type-array-list-where-length"
        category: "globals"
        tags: [globals arrays list where closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [[1 2] [3 4]] | global-define --type "array{list:int:4:2}" samples'
            '  (((global-get samples) | where {|x| ($x | length) == 2 } | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-list-any-get"
        category: "globals"
        tags: [globals arrays list any closure get global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [[1 2] [3 4]] | global-define --type "array{list:int:4:2}" samples'
            '  ((global-get samples) | any {|x| (($x | get 1) == 4) })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-define-type-array-list-all-length"
        category: "globals"
        tags: [globals arrays list all closure length global-define initializer accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [[1 2] [3 4]] | global-define --type "array{list:int:4:2}" samples'
            '  ((global-get samples) | all {|x| (($x | length) == 2) })'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
