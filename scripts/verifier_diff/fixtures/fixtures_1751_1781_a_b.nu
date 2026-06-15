const VERIFIER_DIFF_FIXTURES_1751_1781_A_B = [
    {
        name: "core-scalar-math-abs"
        category: "language-core"
        tags: [scalar math abs]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  -42 | math abs'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-abs-runtime"
        category: "language-core"
        tags: [scalar math abs runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | math abs) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-abs-float-folded"
        category: "language-core"
        tags: [scalar aggregate list math abs float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (-2.5 | math abs | fill --alignment right --character "0" --width 1 | str starts-with "2.5") and ([-2 -1.5] | math abs | str join "," | str starts-with "2,1.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-abs-float-describe"
        category: "language-core"
        tags: [scalar aggregate list math abs float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let scalar_desc_ok = (-2.5 | math abs | describe | str starts-with "float")'
            '  let list_desc_ok = ([-2 -1.5] | math abs | describe | str starts-with "list<any>")'
            '  $scalar_desc_ok and $list_desc_ok'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-abs-float-list-fill"
        category: "language-core"
        tags: [aggregate list math abs float fill str join metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-2 -1.5] | math abs | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "0002,01.5"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
