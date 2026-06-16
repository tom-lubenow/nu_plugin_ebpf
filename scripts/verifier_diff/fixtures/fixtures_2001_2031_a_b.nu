const VERIFIER_DIFF_FIXTURES_2001_2031_A_B = [
    {
        name: "core-runtime-string-index-of-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "l" --range 2..5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-negative-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "l" --range 1..-2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-negative-start-range-tracked-length"
        category: "language-core"
        tags: [string str index-of range runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "l" --range -3..'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
