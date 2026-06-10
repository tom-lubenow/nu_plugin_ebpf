const VERIFIER_DIFF_FIXTURES_2001_2031 = [
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
