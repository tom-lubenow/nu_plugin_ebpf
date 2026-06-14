const VERIFIER_DIFF_FIXTURES_1782_1812_A = [
    {
        name: "core-runtime-match-integer-range-open-lower"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { ..2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-open-lower-right-exclusive"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { ..<2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-open-upper"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 1.. => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-variable-binding"
        category: "language-core"
        tags: [control-flow "match" binding scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = ((random int | bits and 3) - 2)'
            '  match $n { $x => ($x + 1) }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-abs-sum"
        category: "language-core"
        tags: [aggregate list math abs sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-2 -1 0 3] | math abs | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-abs-runtime"
        category: "language-core"
        tags: [aggregate list math abs runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | math abs | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-integer-identity"
        category: "language-core"
        tags: [aggregate list math ceil floor round]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([-2 0 3] | math ceil | math floor | math round | math sum) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
        name: "core-scalar-math-integer-identity-runtime"
        category: "language-core"
        tags: [scalar math ceil floor round runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | math ceil | math floor | math round) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-integer-identity-runtime"
        category: "language-core"
        tags: [aggregate list math ceil floor round runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | math ceil | math floor | math round | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-floor-divide-constant"
        category: "language-core"
        tags: [scalar math floor-divide constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (5 // 2) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-integer-pow-runtime-base"
        category: "language-core"
        tags: [scalar math pow runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (((random int | bits and 255) ** 2) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-binary"
        category: "language-core"
        tags: [scalar bits and or xor]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((5 | bits and 3) == 1) and ((5 | bits or 2) == 7) and ((5 | bits xor 3) == 6)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
