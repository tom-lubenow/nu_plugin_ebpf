const VERIFIER_DIFF_FIXTURES_2001_2031_A_C = [
    {
        name: "core-runtime-string-index-of-empty-negative-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "" --range 1..-2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-negative-start-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "" --range -3..'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-end-negative-range-tracked-length"
        category: "language-core"
        tags: [string str index-of end range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of --end "" --range 1..-2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-empty-end-range-tracked-length"
        category: "language-core"
        tags: [string str index-of end range empty runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of --end "" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-range"
        category: "language-core"
        tags: [string str index-of range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str index-of "bc" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-range-explicit-step"
        category: "language-core"
        tags: [string str index-of range step]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str index-of "bc" --range 2..4..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
