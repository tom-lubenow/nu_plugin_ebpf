const VERIFIER_DIFF_FIXTURES_1657_1687 = [
    {
        name: "core-list-first-negative-count-reject"
        category: "language-core"
        tags: [aggregate list first reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first count must be non-negative"
    }
    {
        name: "core-list-last-negative-count-reject"
        category: "language-core"
        tags: [aggregate list last reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last count must be non-negative"
    }
    {
        name: "core-list-get-negative-index-reject"
        category: "language-core"
        tags: [aggregate list get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let i = -1'
            '  [10 20 30] | get $i'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index must be non-negative"
    }
    {
        name: "core-list-get-out-of-bounds-reject"
        category: "language-core"
        tags: [aggregate list get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | get 3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index 3 is out of bounds"
    }
    {
        name: "core-list-take-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 2 | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-oversized-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 4 | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-zero-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 0 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-negative-count-reject"
        category: "language-core"
        tags: [aggregate list take reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take count must be non-negative"
    }
    {
        name: "core-list-reverse"
        category: "language-core"
        tags: [aggregate list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-reverse-after-take"
        category: "language-core"
        tags: [aggregate list reverse take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 2 | reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-uniq"
        category: "language-core"
        tags: [aggregate list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 10 30 20] | uniq | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-uniq-empty"
        category: "language-core"
        tags: [aggregate list uniq empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | uniq | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort"
        category: "language-core"
        tags: [aggregate list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [30 10 20] | sort | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort-reverse"
        category: "language-core"
        tags: [aggregate list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 30 20] | sort --reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort-capacity-reject"
        category: "language-core"
        tags: [aggregate list sort reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 16 | sort | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort supports stack-backed numeric lists with capacity <= 16"
    }
    {
        name: "core-list-compact"
        category: "language-core"
        tags: [aggregate list compact]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-compact-empty"
        category: "language-core"
        tags: [aggregate list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact --empty | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-compact-column-reject"
        category: "language-core"
        tags: [aggregate list compact reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact does not accept column arguments"
    }
    {
        name: "core-record-list-compact-column-length"
        category: "language-core"
        tags: [aggregate record list compact column length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 8 } { pid: 9 cpu: 4 }] | compact cpu | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-compact-empty-column-length"
        category: "language-core"
        tags: [aggregate record list compact empty column length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{ pid: 7 comm: "" } { pid: 8 comm: "nu" } { pid: 9 }] | compact --empty comm | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find"
        category: "language-core"
        tags: [aggregate list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | find 20 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find-missing"
        category: "language-core"
        tags: [aggregate list find empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | find 99 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-default"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-zero-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 0 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-oversized-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 4 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-negative-count-reject"
        category: "language-core"
        tags: [aggregate list drop reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop count must be non-negative"
    }
    {
        name: "core-list-skip-default"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-count"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-oversized-count"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip 4 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-negative-count-reject"
        category: "language-core"
        tags: [aggregate list skip reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip count must be non-negative"
    }
]
