const VERIFIER_DIFF_FIXTURES_1938_1968_A = [
    {
        name: "core-binary-bytes-split-string-separator-unequal-last"
        category: "language-core"
        tags: [binary bytes split string separator unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 62] | bytes split "--" | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-input-length"
        category: "language-core"
        tags: [binary bytes split empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes split 0x[20] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-metadata-predicates"
        category: "language-core"
        tags: [binary bytes split unequal empty length is-empty is-not-empty metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let unequal_len_ok = ((0x[61 20 62 62] | bytes split 0x[20] | length) == 2)'
            '  let unequal_empty_ok = not (0x[61 20 62 62] | bytes split 0x[20] | is-empty)'
            '  let empty_input_len_ok = ((0x[] | bytes split 0x[20] | length) == 1)'
            '  let empty_input_not_empty_ok = (0x[] | bytes split 0x[20] | is-not-empty)'
            '  $unequal_len_ok and ($unequal_empty_ok and ($empty_input_len_ok and $empty_input_not_empty_ok))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-is-empty"
        category: "language-core"
        tags: [string is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length"
        category: "language-core"
        tags: [string str length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-grapheme-clusters"
        category: "language-core"
        tags: [string str length grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ" | str length --grapheme-clusters'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-chars"
        category: "language-core"
        tags: [string str length chars]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ("Amélie" | str length --chars) == 7'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-sum"
        category: "language-core"
        tags: [string list str length sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "bb"] | str length | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-grapheme-clusters-sum"
        category: "language-core"
        tags: [string list str length grapheme-clusters sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["🇯🇵" "ほげ"] | str length --grapheme-clusters | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-chars-sum"
        category: "language-core"
        tags: [string list str length chars sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (["Amélie" "字"] | str length --chars | math sum) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-too-long"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str starts-with "abcdefghijklmnopqrstu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-starts-with-tracked-length"
        category: "language-core"
        tags: [string str starts-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with "hello"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-ignore-case"
        category: "language-core"
        tags: [string str starts-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str starts-with --ignore-case "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-starts-with-join"
        category: "language-core"
        tags: [string list str starts-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "xbc"] | str starts-with "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str ends-with "def"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
