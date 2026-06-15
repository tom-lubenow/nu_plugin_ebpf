const VERIFIER_DIFF_FIXTURES_1719_1750_B_C = [
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
]
