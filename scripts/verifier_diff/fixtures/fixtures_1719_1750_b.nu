const VERIFIER_DIFF_FIXTURES_1719_1750_B = [
    {
        name: "core-list-math-min-max-mixed-numeric"
        category: "language-core"
        tags: [aggregate list math min max float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1 2.5 3.5] | math min) == 1) and (([1.5 2.5 3] | math max) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-results-fill"
        category: "language-core"
        tags: [aggregate list math min max median float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1.5 2 3] | math min | fill --alignment right --character "0" --width 4 | str starts-with "01.5") and ([1 2.0 2] | math max | fill --alignment right --character "0" --width 4 | str starts-with "0002")) and (([1 3] | math median | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1.5 3.5 10] | math median | fill --alignment right --character "0" --width 4 | str starts-with "03.5"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-sum-product-fill"
        category: "language-core"
        tags: [aggregate list math sum product float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 2] | math sum | fill --alignment right --character "0" --width 4 | str starts-with "03.5") and ([1.5 2] | math product | fill --alignment right --character "0" --width 4 | str starts-with "0003")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-float-sum-product-describe"
        category: "language-core"
        tags: [aggregate list math sum product float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 2] | math sum | describe | str starts-with "float") and ([1.5 2] | math product | describe | str starts-with "float")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-fill"
        category: "language-core"
        tags: [aggregate list math avg float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3] | math avg | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1.0 2] | math avg | fill --alignment right --character "0" --width 4 | str starts-with "01.5")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-describe"
        category: "language-core"
        tags: [aggregate list math avg float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3] | math avg | describe | str starts-with "float"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-filesize-duration"
        category: "language-core"
        tags: [aggregate list math avg filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1kb 2kb 2kb] | math avg | describe | str starts-with "filesize") and ([1sec 2sec 2sec] | math avg | describe | str starts-with "duration")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
