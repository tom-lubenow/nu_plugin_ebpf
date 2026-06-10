const VERIFIER_DIFF_FIXTURES_1969_2000 = [
    {
        name: "core-int-fill-right"
        category: "language-core"
        tags: [int fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  42 | fill --alignment right --character "0" --width 5 | str starts-with "00042"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-unsigned-int-fill"
        category: "language-core"
        tags: [int runtime fill context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | fill | str starts-with "0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-fill-right"
        category: "language-core"
        tags: [float fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.25 | fill --alignment right --character "0" --width 6 | str starts-with "001.25"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-filesize-fill-right"
        category: "language-core"
        tags: [filesize fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1kb | fill --alignment right --character "_" --width 8 | str starts-with "____1000"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-named-prompt"
        category: "language-core"
        tags: [string char named]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char prompt | str starts-with "▶"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-named-extra-string-args"
        category: "language-core"
        tags: [string char named rest]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char prompt ignored 1f354 | str starts-with "▶"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-unicode-codepoints"
        category: "language-core"
        tags: [string char unicode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode 1F468 200D 1F466 | str starts-with "👨‍👦"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-integer-codepoints"
        category: "language-core"
        tags: [string char integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --integer 65 66 | str starts-with "AB"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-fill-center-join"
        category: "language-core"
        tags: [string list fill center join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "bc"] | fill --alignment center --character "_" --width 4 | str join "," | str starts-with "_a__,_bc_"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-int-list-fill-right-join"
        category: "language-core"
        tags: [int list fill right join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 23] | fill --alignment right --character "0" --width 3 | str join "," | str starts-with "001,023"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-mixed-list-fill-right-join"
        category: "language-core"
        tags: [int float filesize string list fill right join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 1kb "x"] | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "0001,01.5,1000,000x"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-string-group-join"
        category: "language-core"
        tags: [list split-list string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x" "c" "d" "x" "e" "f"] | split list "x" | get 1 | str join "-" | str starts-with "c-d"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-after-string-group-join"
        category: "language-core"
        tags: [list split-list after string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x" "c" "x" "e" "f"] | split list --split after "x" | get 1 | str join "-" | str starts-with "c-x"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-before-string-group-join"
        category: "language-core"
        tags: [list split-list before string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x" "c" "x" "d"] | split list --split before "x" | get 1 | str join "-" | str starts-with "x-c"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-regex-after-string-group-join"
        category: "language-core"
        tags: [list split-list regex after string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x1" "c" "x22" "e" "f"] | split list --regex --split after "x\\d+" | get 1 | str join "-" | str starts-with "c-x22"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-heterogeneous-materialized-reject"
        category: "language-core"
        tags: [aggregate list split-list reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x" "b" "c" "x" "d"] | split list "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list result requires homogeneous fixed-layout groups"
    }
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
