const VERIFIER_DIFF_FIXTURES_1782_1812_A_B = [
    {
        name: "core-scalar-math-float-rounding"
        category: "language-core"
        tags: [scalar math ceil floor round float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(1.25 | math ceil) (-1.25 | math floor) (-2.5 | math round)] | math sum) == -3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-rounding"
        category: "language-core"
        tags: [aggregate list math round float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 -1.5] | math round | str join "," | str starts-with "1,2,-2"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-round-precision-folded"
        category: "language-core"
        tags: [scalar aggregate list math round precision float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((3.1415 | math round --precision 2 | fill --alignment right --character "0" --width 1 | str starts-with "3.14") and (314.15 | math round -p -1 | fill --alignment right --character "0" --width 1 | str starts-with "310")) and ([3.1415 -2.675] | math round -p 2 | str join "," | str starts-with "3.14,-2.68")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-round-precision-list-fill"
        category: "language-core"
        tags: [aggregate list math round precision float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [3.1415 -2.675] | math round -p 2 | fill --alignment right --character "0" --width 5 | str join "," | str starts-with "03.14,-2.68"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-round-precision-describe"
        category: "language-core"
        tags: [scalar aggregate list math round precision float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (3.1415 | math round --precision 2 | describe | str starts-with "float") and ([3.1415 -2.675] | math round --precision 2 | describe | str starts-with "list<float>")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
