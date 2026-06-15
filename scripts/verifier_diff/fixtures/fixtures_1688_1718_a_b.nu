const VERIFIER_DIFF_FIXTURES_1688_1718_A_B = [
    {
        name: "core-list-where"
        category: "language-core"
        tags: [aggregate list where closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | where {|x| $x > 15 } | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-where-true-first"
        category: "language-core"
        tags: [aggregate list where closure first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([10 20 30] | where {|x| true } | first) == 10'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-where-false-is-empty"
        category: "language-core"
        tags: [aggregate list where closure is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([10 20 30] | where {|x| false } | is-empty) == true'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any"
        category: "language-core"
        tags: [aggregate list any closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all"
        category: "language-core"
        tags: [aggregate list all closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | all {|x| $x > 5 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any-empty"
        category: "language-core"
        tags: [aggregate list any closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all-empty"
        category: "language-core"
        tags: [aggregate list all closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | all {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
