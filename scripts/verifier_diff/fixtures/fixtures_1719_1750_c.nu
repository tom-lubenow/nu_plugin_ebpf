const VERIFIER_DIFF_FIXTURES_1719_1750_C = [
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
        name: "core-math-inverse-list-fill-arcs"
        category: "language-core"
        tags: [aggregate list math arcsin arccos float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0 1] | math arcsin | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,1.570") and ([1 0] | math arccos | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,1.570")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-inverse-list-fill-atan-asinh"
        category: "language-core"
        tags: [aggregate list math arctan arcsinh float fill str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0 1] | math arctan | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,0.785") and ([0 1] | math arcsinh | fill --alignment right --character "0" --width 4 | str join "," | str starts-with "00.0,0.881")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-trig-family-scalar-describe"
        category: "language-core"
        tags: [scalar math sin sinh arcsin float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((0 | math sin | describe | str starts-with "float") and (0 | math sinh | describe | str starts-with "float")) and (0 | math arcsin | describe | str starts-with "float")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-trig-family-list-describe"
        category: "language-core"
        tags: [aggregate list math sin cosh arcsin arcsinh degrees float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([0 90] | math sin --degrees | describe | str starts-with "list<float>") and ([0 0] | math cosh | describe | str starts-with "list<float>")) and ([0 1] | math arcsin | describe | str starts-with "list<float>")) and ([0 1] | math arcsinh | describe | str starts-with "list<float>")'
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
        name: "core-math-stats-complementary-fill"
        category: "language-core"
        tags: [aggregate list math variance stddev sample float fill]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3 4 5] | math variance --sample | fill --alignment right --character "0" --width 4 | str starts-with "02.5") and ([1 2 3 4 5] | math stddev | fill --alignment right --character "0" --width 4 | str starts-with "1.414")'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-math-stats-describe"
        category: "language-core"
        tags: [aggregate list math variance stddev float describe metadata-only]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1 2 3 4 5] | math variance | describe | str starts-with "float") and ([1 2 3 4 5] | math stddev | describe | str starts-with "float")'
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
        name: "core-list-math-unit-reducer-values"
        category: "language-core"
        tags: [aggregate list math sum min max filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((([1kb 2kb] | math sum) == 3000) and (([1sec 2sec] | math sum) == 3000000000)) and ((([1kb 2] | math max) == 1000) and (([1sec 2] | math min) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-avg-unit-values"
        category: "language-core"
        tags: [aggregate list math avg filesize duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([1kb 2kb 2kb] | math avg) == 1666) and (([1sec 2sec 2sec] | math avg) == 1666666666)'
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
