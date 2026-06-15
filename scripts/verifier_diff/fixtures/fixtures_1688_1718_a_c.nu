const VERIFIER_DIFF_FIXTURES_1688_1718_A_C = [
    {
        name: "core-list-append-large-seq-get"
        category: "language-core"
        tags: [aggregate list seq append get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 59 | append 60 | get 60'
            '}'
        ]
        local: "accept"
        kernel: "accept"
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
