const VERIFIER_DIFF_FIXTURES_1938_2000 = [
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
    {
        name: "core-string-ends-with-too-long"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str ends-with "abcdef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-ends-with-tracked-length"
        category: "language-core"
        tags: [string str ends-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with "lo"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-ignore-case"
        category: "language-core"
        tags: [string str ends-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str ends-with --ignore-case "CD"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-ends-with-join"
        category: "language-core"
        tags: [string list str ends-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "abx"] | str ends-with "c" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-contains-tracked-length"
        category: "language-core"
        tags: [string str contains runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains "ll"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-join"
        category: "language-core"
        tags: [string list str contains join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "def"] | str contains "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-ignore-case-join"
        category: "language-core"
        tags: [string list str contains ignore-case join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["Abc" "def"] | str contains --ignore-case "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-missing"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "zz"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-ignore-case"
        category: "language-core"
        tags: [string str contains ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str contains --ignore-case "bc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-distance"
        category: "language-core"
        tags: [string str distance]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nushell" | str distance "nutshell"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-join-scalar"
        category: "language-core"
        tags: [string str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str join "-" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-join"
        category: "language-core"
        tags: [string list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-scalar-list-join"
        category: "language-core"
        tags: [string list scalar str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 1kb 1sec 0x[01 02] true null] | str join ":" | str starts-with "1:1.5:1.0 kB:1sec:[1, 2]:true:"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-aggregate-list-join"
        category: "language-core"
        tags: [string list aggregate record str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let records = ([{a: 1 b: 2} {c: 3}] | str join ":")'
            '  let lists = ([[1 2] [3]] | str join ":")'
            '  (($records | str starts-with "{a: 1") and ($records | str contains "b: 2}:{c: 3}")) and (($lists | str starts-with "[1") and ($lists | str contains "2]:[3]"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-fill-right"
        category: "language-core"
        tags: [string fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab" | fill --alignment right --character "0" --width 5 | str starts-with "000ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
