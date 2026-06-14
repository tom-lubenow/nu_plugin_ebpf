const VERIFIER_DIFF_FIXTURES_1969_2000_A = [
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
        name: "core-list-split-list-regex-string-group-join"
        category: "language-core"
        tags: [list split-list regex string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x1" "c" "d" "x22" "e" "f"] | split list --regex "x\\d+" | get 1 | str join "-" | str starts-with "c-d"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-heterogeneous-metadata"
        category: "language-core"
        tags: [list split-list heterogeneous metadata accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let join_ok = (["a" "x" "b" "c" "x" "d"] | split list "x" | get 1 | str join "-" | str starts-with "b-c")'
            '  $join_ok and (["a" "x" "b" "c" "x" "d"] | split list "x" | describe | str starts-with "list<list<string>>")'
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
]
