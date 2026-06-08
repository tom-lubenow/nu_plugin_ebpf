const VERIFIER_DIFF_FIXTURES_1751_1812 = [
    {
        name: "core-list-math-median-mixed-numeric"
        category: "language-core"
        tags: [aggregate list math median float constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([1.5 3 10.5] | math median) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-math-median"
        category: "language-core"
        tags: [aggregate list seq math median]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 5 | math median'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-math-median"
        category: "language-core"
        tags: [aggregate list math median runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  let m = (seq 10 10 20 | append $n | math median)'
            '  ($m >= 10) and ($m <= 20)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-mode"
        category: "language-core"
        tags: [aggregate list math mode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [5 1 5 2 1] | math mode | str join "-" | str starts-with "1-5"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-list-math-mode"
        category: "language-core"
        tags: [aggregate list math mode runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  (seq 1 1 3 | append $n | math mode | length) >= 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-mode-empty"
        category: "language-core"
        tags: [aggregate list math mode empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([] | math mode | length) == 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min-single"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum-empty-reject"
        category: "language-core"
        tags: [aggregate list math sum reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | math sum'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math sum requires a non-empty stack-backed numeric list"
    }
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
        name: "core-scalar-math-div-mod-runtime"
        category: "language-core"
        tags: [scalar math divide modulo runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = ((random int | bits and 255) + 1)'
            '  (($n / 3) >= 0) and (($n mod 3) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-math-arithmetic-runtime"
        category: "language-core"
        tags: [scalar math add subtract multiply runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 255)'
            '  ((($n + 7) - 3) * 2) >= 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-boolean-runtime"
        category: "language-core"
        tags: [scalar comparison boolean runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  ($a == $b) or ($a != $b)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-ordering-runtime"
        category: "language-core"
        tags: [scalar comparison ordering runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  ($a <= $b) or ($a > $b)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-comparison-grouped-boolean-runtime"
        category: "language-core"
        tags: [scalar comparison boolean runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let a = (random int | bits and 255)'
            '  let b = (random int | bits and 255)'
            '  (($a == $b) or ($a != $b)) and (($a <= $b) or ($a > $b)) and (($a < ($b + 1)) or ($a >= ($b + 1)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-if-logical-not"
        category: "language-core"
        tags: [control-flow "if" scalar logical "not" runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 1)'
            '  if (not ($n == 0)) { $n + 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer"
        category: "language-core"
        tags: [control-flow "match" scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0 => 10, 1 => 20, _ => 30 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-bool"
        category: "language-core"
        tags: [control-flow "match" scalar bool runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let b = ((random int | bits and 1) == 1)'
            '  match $b { true => 10, false => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-nothing"
        category: "language-core"
        tags: [control-flow "match" scalar nothing runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let x = null'
            '  match $x { null => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-match-string"
        category: "language-core"
        tags: [control-flow "match" scalar string constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let s = "hi"'
            '  match $s { "hi" => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-tracked-string"
        category: "language-core"
        tags: [control-flow "match" scalar string runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "lo" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  match $left { "lo" => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-match-filesize"
        category: "language-core"
        tags: [control-flow "match" scalar filesize constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let size = 1kb'
            '  match $size { 1kb => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-equality-filesize-int"
        category: "language-core"
        tags: [scalar comparison filesize constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  if (1kb == 1000) { 10 } else { 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-match-duration"
        category: "language-core"
        tags: [control-flow "match" scalar duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let elapsed = 1ns'
            '  match $elapsed { 1ns => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-constant-equality-duration-int"
        category: "language-core"
        tags: [scalar comparison duration constant]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  if (1ns == 1) { 10 } else { 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-or-pattern"
        category: "language-core"
        tags: [control-flow "match" "or-pattern" scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0 | 1 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0..2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-explicit-step"
        category: "language-core"
        tags: [control-flow "match" range step scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 15)'
            '  match $n { 0..2..10 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-right-exclusive"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 0..<2 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-match-integer-range-descending-right-exclusive"
        category: "language-core"
        tags: [control-flow "match" range scalar integer runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  match $n { 2..<0 => 10, _ => 20 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-scalar-bits-binary-runtime"
        category: "language-core"
        tags: [scalar bits and or xor runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((random int | bits and 3) + (random int | bits or 2) + (random int | bits xor 1)) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary"
        category: "language-core"
        tags: [aggregate list bits and or xor]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits and 2 | bits or 8 | bits xor 1 | math sum) == 31'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-runtime"
        category: "language-core"
        tags: [aggregate list bits and or xor runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits and 3 | bits or 4 | bits xor 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits and or xor endian]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[ab cd] | bits and 0x[99 99] | bytes starts-with 0x[89 89]) and (0x[c0 ff ee] | bits or 0x[ff] --endian big | bytes starts-with 0x[c0 ff ff]) and (0x[ff] | bits xor 0x[12 34 56] --endian little | bytes starts-with 0x[ed 34 56])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[aa] 0x[bb cc]] | bits xor 0x[ff] | bytes collect | bytes length) == 3) and (([0x[aa] 0x[bb cc]] | bits xor 0x[ff] | length) == 2)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-binary-get-fold"
        category: "language-core"
        tags: [aggregate list binary bits xor get bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01] 0x[02 03]] | bits xor 0x[ff] | get 1 | bytes starts-with 0x[fd fc]) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed"
        category: "language-core"
        tags: [scalar bits "not" signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (4 | bits not --signed) == -5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-signed-runtime"
        category: "language-core"
        tags: [scalar bits "not" signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits not --signed) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits "not" number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits not --number-bytes 1) >= 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-signed"
        category: "language-core"
        tags: [aggregate list bits "not" signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits not --signed | math sum) == -12'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-signed-runtime"
        category: "language-core"
        tags: [aggregate list bits "not" signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits not --signed | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits "not" default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int | bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not default auto-width integer mode requires compile-time known input"
    }
    {
        name: "core-scalar-bits-not-default"
        category: "language-core"
        tags: [scalar bits "not"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits not) == 251) and ((256 | bits not) == 65279) and ((65536 | bits not) == 4294901759) and ((4294967296 | bits not) == 140733193388031)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-number-bytes"
        category: "language-core"
        tags: [scalar bits "not" number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits not --number-bytes 8) == 140737488355323) and ((-130 | bits not --number-bytes 1) == 129)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-not-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits "not" signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[ff 00 7f] | bits not | bytes starts-with 0x[00 ff 80]) and (0x[aa 55] | bits not --number-bytes 8 | bytes starts-with 0x[55 aa]) and (0x[c3] | bits not --signed --number-bytes 8 | bytes starts-with 0x[3c])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[ff] 0x[00 01]] | bits not | bytes collect | bytes length) == 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
