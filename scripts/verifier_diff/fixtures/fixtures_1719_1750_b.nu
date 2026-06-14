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
    {
        name: "core-math-trig-folded"
        category: "language-core"
        tags: [scalar aggregate list math sin cos tan float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sin | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math cos | fill --alignment right --character "0" --width 4 | str starts-with "0001")) and ((0 | math tan | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([0 0] | math cos | str join "," | str starts-with "1.0,1.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-trig-list-fill"
        category: "language-core"
        tags: [aggregate list math sin cos tan float degrees fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([0 90] | math sin --degrees | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,01.0") and ([0 0] | math cos | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "01.0,01.0")) and ([0 0] | math tan | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,00.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-hyperbolic-folded"
        category: "language-core"
        tags: [scalar aggregate list math sinh cosh tanh float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sinh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math cosh | fill --alignment right --character "0" --width 4 | str starts-with "0001")) and ((0 | math tanh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and ([0 0] | math cosh | str join "," | str starts-with "1.0,1.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-hyperbolic-list-fill"
        category: "language-core"
        tags: [aggregate list math sinh cosh tanh float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([0 0] | math sinh | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,00.0") and ([0 0] | math cosh | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "01.0,01.0")) and ([0 0] | math tanh | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,00.0"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-inverse-folded"
        category: "language-core"
        tags: [scalar aggregate list math inverse float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((0 | math arcsin | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (1 | math arccos | fill --alignment right --character "0" --width 4 | str starts-with "0000")) and ((0 | math arctan | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math arcsinh | fill --alignment right --character "0" --width 4 | str starts-with "0000"))) and (((1 | math arccosh | fill --alignment right --character "0" --width 4 | str starts-with "0000") and (0 | math arctanh | fill --alignment right --character "0" --width 4 | str starts-with "0000")) and ([0 1] | math arcsin | str join "," | str starts-with "0.0,1.5707963267948966"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-degrees-folded"
        category: "language-core"
        tags: [scalar aggregate list math degrees inverse sin cos tan float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((90 | math sin --degrees | fill --alignment right --character "0" --width 4 | str starts-with "0001") and (180 | math cos --degrees | fill --alignment right --character "0" --width 1 | str starts-with "-1")) and (45 | math tan --degrees | fill --alignment right --character "0" --width 1 | str starts-with "0.999")) and (((1 | math arcsin --degrees | fill --alignment right --character "0" --width 1 | str starts-with "90") and (-1 | math arccos --degrees | fill --alignment right --character "0" --width 1 | str starts-with "180")) and ((1 | math arctan -d | fill --alignment right --character "0" --width 1 | str starts-with "45") and ([0 1] | math arcsin -d | str join "," | str starts-with "0.0,90.0")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-stats-folded"
        category: "language-core"
        tags: [aggregate list math variance stddev sample float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3 4 5] | math variance | fill --alignment right --character "0" --width 4 | str starts-with "0002") and ([1 2 3 4 5] | math stddev --sample | fill --alignment right --character "0" --width 4 | str starts-with "1.581")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-filesize-duration"
        category: "language-core"
        tags: [aggregate list math filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1kb 2kb] | math sum | describe | str starts-with "filesize") and (([1sec 2sec] | math sum | describe | str starts-with "duration"))) and ((([1kb 2] | math max | describe | str starts-with "filesize") and ([1sec 2] | math min) == 2) and (([1kb 2kb] | math median | describe | str starts-with "filesize") and ([1sec 2sec] | math median | describe | str starts-with "duration")))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-median"
        category: "language-core"
        tags: [aggregate list math median]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math median'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
