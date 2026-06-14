const VERIFIER_DIFF_FIXTURES_2001_2031_B = [
    {
        name: "core-string-index-of-open-end-range"
        category: "language-core"
        tags: [string str index-of range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str index-of "bc" --range 2..'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-grapheme-clusters"
        category: "language-core"
        tags: [string str index-of grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ ふが ぴよ" | str index-of --grapheme-clusters "ふが"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-grapheme-clusters-from-end"
        category: "language-core"
        tags: [string str index-of end grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b🇯🇵c" | str index-of --grapheme-clusters --end "🇯🇵"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-index-of-grapheme-clusters-range"
        category: "language-core"
        tags: [string str index-of range grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ほげ ふが" | str index-of --grapheme-clusters "ふ" --range 6..9'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-join"
        category: "language-core"
        tags: [string list str index-of join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ababa" "xaba"] | str index-of "ba" | str join "-" | str starts-with "1-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-from-end-join"
        category: "language-core"
        tags: [string list str index-of end join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ababa" "baba"] | str index-of --end "ba" | str join "-" | str starts-with "3-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-range-join"
        category: "language-core"
        tags: [string list str index-of range join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abcabc" "zzbc"] | str index-of "bc" --range 2..5 | str join "-" | str starts-with "4-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-index-of-grapheme-clusters-join"
        category: "language-core"
        tags: [string list str index-of grapheme-clusters join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["🇯🇵ほげ ふが" "a🇯🇵b"] | str index-of --grapheme-clusters "🇯🇵" | str join "-" | str starts-with "0-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring"
        category: "language-core"
        tags: [string str substring]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str substring 1..3 | str starts-with "bcd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring-explicit-step"
        category: "language-core"
        tags: [string str substring range step]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str substring 1..3..4 | str starts-with "bcde"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-substring-join"
        category: "language-core"
        tags: [string list str substring join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abcd" "wxyz"] | str substring 1..2 | str join "-" | str starts-with "bc-xy"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring-negative-end"
        category: "language-core"
        tags: [string str substring]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str substring 1..-2 | str starts-with "bcde"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-substring-grapheme-clusters"
        category: "language-core"
        tags: [string str substring grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ ふが ぴよ" | str substring --grapheme-clusters 4..5 | str starts-with "ふが"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-replace"
        category: "language-core"
        tags: [string str replace]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcabc" | str replace "ab" "XY" | str starts-with "XYc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-replace-join"
        category: "language-core"
        tags: [string list str replace join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "aba"] | str replace "a" "z" | str join "-" | str starts-with "zbc-zba"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-replace-regex-join"
        category: "language-core"
        tags: [string list str replace regex join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc123" "x9"] | str replace --regex "([a-z]+)([0-9]+)" "${2}" | str join "-" | str starts-with "123-9"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
