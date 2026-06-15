const VERIFIER_DIFF_FIXTURES_1969_2000_A_C = [
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
]
