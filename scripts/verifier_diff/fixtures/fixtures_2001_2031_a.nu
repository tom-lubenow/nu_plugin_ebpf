const VERIFIER_DIFF_FIXTURES_2001_2031_A = [
    {
        name: "core-string-index-of"
        category: "language-core"
        tags: [string str index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ababa" | str index-of "ba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-missing"
        category: "language-core"
        tags: [string str index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str index-of "zz"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-from-end"
        category: "language-core"
        tags: [string str index-of end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ababa" | str index-of --end "ba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-tracked-length"
        category: "language-core"
        tags: [string str index-of runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of "ll"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-index-of-end-tracked-length"
        category: "language-core"
        tags: [string str index-of end runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str index-of --end "l"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
