const VERIFIER_DIFF_FIXTURES_1657_1687_B = [
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
        name: "core-list-compact-column"
        category: "language-core"
        tags: [aggregate list compact column accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact value | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
