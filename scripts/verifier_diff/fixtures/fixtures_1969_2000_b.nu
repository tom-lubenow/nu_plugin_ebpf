const VERIFIER_DIFF_FIXTURES_1969_2000_B = [
    {
        name: "core-string-split-chars-join"
        category: "language-core"
        tags: [string split chars join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b" | split chars | str join "-" | str starts-with "a-🇯-🇵-b"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-chars-grapheme-join"
        category: "language-core"
        tags: [string split chars grapheme join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b" | split chars --grapheme-clusters | str join "-" | str starts-with "a-🇯🇵-b"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-words-join"
        category: "language-core"
        tags: [string split words join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello, to the world!" | split words | str join "-" | str starts-with "hello-to-the-world"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-words-min-utf8-join"
        category: "language-core"
        tags: [string split words min utf8 join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a é ee" | split words --min-word-length 2 --utf-8-bytes | str join "-" | str starts-with "é-ee"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-nested-metadata"
        category: "language-core"
        tags: [string list split chars words nested join length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let chars = (["ab" "cd"] | split chars | str join ":")'
            '  let words = (["a b" "c d e"] | split words | str join ":")'
            '  (($chars | str starts-with "[a") and ($chars | str contains "b]:[c")) and ((($words | str starts-with "[a") and ($words | str contains "e]")) and ((["ab" "cd"] | split chars | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-nested-describe-predicates"
        category: "language-core"
        tags: [string list split chars words nested describe is-empty is-not-empty metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let chars_desc_ok = (["ab" "cd"] | split chars | describe | str starts-with "list<list<string>>")'
            '  let words_desc_ok = (["a b" "c d e"] | split words | describe | str starts-with "list<list<string>>")'
            '  let chars_empty_ok = not (["ab" "cd"] | split chars | is-empty)'
            '  let words_not_empty_ok = (["a b" "c d e"] | split words | is-not-empty)'
            '  $chars_desc_ok and ($words_desc_ok and ($chars_empty_ok and $words_not_empty_ok))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-options-get-metadata"
        category: "language-core"
        tags: [string list split chars words grapheme min get join metadata]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let chars = (["a🇯🇵" "cd"] | split chars --grapheme-clusters | get 0 | str join "-")'
            '  let words = (["aa bbb" "c éé ee"] | split words --min-word-length 2 --grapheme-clusters | get 1 | str join "-")'
            '  ($chars | str starts-with "a-🇯🇵") and ($words | str starts-with "éé-ee")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-row-join"
        category: "language-core"
        tags: [string split row join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "alpha,beta,gamma" | split row "," | str join "-" | str starts-with "alpha-beta-gamma"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-row-number-join"
        category: "language-core"
        tags: [string list split row number join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a,b,c" "d,e"] | split row "," --number 2 | str join "-" | str starts-with "a-b,c-d-e"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-row-regex-number-join"
        category: "language-core"
        tags: [string list split row regex number join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a1b2c" "d33e"] | split row --regex "\\d+" --number 2 | str join "-" | str starts-with "a-b2c-d-e"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-get-field"
        category: "language-core"
        tags: [string str stats record get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "Amélie Amelie" | str stats | get bytes'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-unicode-width-get-field"
        category: "language-core"
        tags: [string str stats record get unicode-width]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "字\r\n字" | str stats | get unicode-width'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-length"
        category: "language-core"
        tags: [string str expand list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-path-length"
        category: "language-core"
        tags: [string str expand list length path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "C:\\{Users,Windows}" | str expand --path | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-empty-length"
        category: "language-core"
        tags: [string str expand list length empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{2..1}B" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-length"
        category: "language-core"
        tags: [string str expand list get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 0 | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 1 | str starts-with "AbDfG"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-range-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{08..10}B" | str expand | get 2 | str starts-with "A10B"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
