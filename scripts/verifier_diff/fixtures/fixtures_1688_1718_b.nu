const VERIFIER_DIFF_FIXTURES_1688_1718_B = [
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
