const VERIFIER_DIFF_FIXTURES_1719_1750_B_B = [
    {
        name: "core-math-sqrt-folded"
        category: "language-core"
        tags: [scalar aggregate list math sqrt float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (9 | math sqrt | fill --alignment right --character "0" --width 4 | str starts-with "0003") and ([4 2.25 9] | math sqrt | str join "," | str starts-with "2.0,1.5,3.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-sqrt-list-fill"
        category: "language-core"
        tags: [aggregate list math sqrt float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [4 2.25 9] | math sqrt | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "02.0,01.5,03.0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-exp-folded"
        category: "language-core"
        tags: [scalar aggregate list math exp float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0 | math exp | fill --alignment right --character "0" --width 4 | str starts-with "0001") and ([0 1] | math exp | str join "," | str starts-with "1.0,2.718281828459045")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-ln-folded"
        category: "language-core"
        tags: [scalar aggregate list math ln float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (1 | math ln | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([1 2] | math ln | str join "," | str starts-with "0.0,0.6931471805599453")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-log-folded"
        category: "language-core"
        tags: [scalar aggregate list math log float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (100 | math log 10 | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([16 8 4] | math log 2 | str join "," | str starts-with "4.0,3.0,2.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-exp-ln-log-list-fill"
        category: "language-core"
        tags: [aggregate list math exp ln log float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0 1] | math exp | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "01.0,2.718") and ([1 2] | math ln | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,0.693")) and ([16 8 4] | math log 2 | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "04.0,03.0,02.0")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-exp-ln-log-scalar-describe"
        category: "language-core"
        tags: [scalar math exp ln log float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math exp | describe | str starts-with "float") and (1 | math ln | describe | str starts-with "float")) and (100 | math log 10 | describe | str starts-with "float")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-exp-ln-log-list-describe"
        category: "language-core"
        tags: [aggregate list math exp ln log float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0 1] | math exp | describe | str starts-with "list<float>") and ([1 2] | math ln | describe | str starts-with "list<float>")) and ([16 8] | math log 2 | describe | str starts-with "list<float>")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
