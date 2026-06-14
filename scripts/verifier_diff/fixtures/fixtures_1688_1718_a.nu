const VERIFIER_DIFF_FIXTURES_1688_1718_A = [
    {
        name: "core-list-append"
        category: "language-core"
        tags: [aggregate list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | append 40 | get 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-prepend"
        category: "language-core"
        tags: [aggregate list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | prepend 5 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-each"
        category: "language-core"
        tags: [aggregate list each closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | each {|x| $x + 1 } | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-list-append-capacity-reject"
        category: "language-core"
        tags: [aggregate list append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 59 | append 60 | get 60'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append would exceed stack-backed numeric list capacity 60"
    }
    {
        name: "core-list-is-empty"
        category: "language-core"
        tags: [aggregate list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-length"
        category: "language-core"
        tags: [aggregate list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-length"
        category: "language-core"
        tags: [string list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-get"
        category: "language-core"
        tags: [string list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | get 1 | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | first | str starts-with "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
