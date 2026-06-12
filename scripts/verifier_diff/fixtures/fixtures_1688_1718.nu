const VERIFIER_DIFF_FIXTURES_1688_1718 = [
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
    {
        name: "core-string-list-last"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | last | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-take"
        category: "language-core"
        tags: [string list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | take 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-skip"
        category: "language-core"
        tags: [string list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | skip 1 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-drop"
        category: "language-core"
        tags: [string list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | drop 1 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first-count"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | first 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last-count"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | last 2 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-reverse"
        category: "language-core"
        tags: [string list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | reverse | str join "-" | str starts-with "ef-cd-ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-append"
        category: "language-core"
        tags: [string list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | append "ef" | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-prepend"
        category: "language-core"
        tags: [string list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | prepend "zz" | str join "-" | str starts-with "zz-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-uniq"
        category: "language-core"
        tags: [string list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ab" "ef" "cd"] | uniq | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort"
        category: "language-core"
        tags: [string list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort | str join "-" | str starts-with "aa-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort-reverse"
        category: "language-core"
        tags: [string list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort --reverse | str join "-" | str starts-with "cd-ab-aa"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-find"
        category: "language-core"
        tags: [string list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef" "cd"] | find "cd" | str join "-" | str starts-with "cd-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-compact-empty"
        category: "language-core"
        tags: [string list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "" "cd"] | compact --empty | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum"
        category: "language-core"
        tags: [aggregate list math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-integer-sum"
        category: "language-core"
        tags: [aggregate list seq math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 5 | math sum) == 15'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-negative-step-join"
        category: "language-core"
        tags: [aggregate list seq str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 5 -2 1 | str join "-" | str starts-with "5-3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
