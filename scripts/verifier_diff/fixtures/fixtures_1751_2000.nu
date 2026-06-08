const VERIFIER_DIFF_FIXTURES_1751_2000 = [
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
    {
        name: "core-list-bits-not-binary-first-last-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" first last bytes length starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[ff] 0x[00 01]] | bits not | first | bytes length) == 1) and (([0x[ff] 0x[00 01]] | bits not | last | bytes starts-with 0x[ff fe]) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-binary-empty-predicate-fold"
        category: "language-core"
        tags: [aggregate list binary bits "not" is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bits not | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-not-default"
        category: "language-core"
        tags: [aggregate list bits "not"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 256 -129] | bits not | math sum) == 65658'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-signed-i64"
        category: "language-core"
        tags: [scalar bits shl shr signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((4 | bits shl 1 --signed --number-bytes 8) == 8) and ((-8 | bits shr 1 --signed --number-bytes 8) == -4)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-i64"
        category: "language-core"
        tags: [aggregate list bits shl signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits shl 1 --signed --number-bytes 8 | math sum) == 18'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits shr signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shr 1 --signed --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-number-bytes"
        category: "language-core"
        tags: [scalar bits shl shr signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((255 | bits shl 1 --number-bytes 1) == 254) and ((-65 | bits shr 1 --number-bytes 1) == -33) and ((127 | bits shl 1 --signed --number-bytes 1) == -2) and ((128 | bits shr 1 --signed --number-bytes 1) == -64) and ((4294967296 | bits shl 1 --number-bytes 8) == 8589934592)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-rotate-binary-bytes"
        category: "language-core"
        tags: [scalar binary bits shl shr rol ror signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (0x[4f f4] | bits shl 4 | bytes starts-with 0x[ff 40]) and (0x[4f f4] | bits shr 4 --signed --number-bytes 8 | bytes starts-with 0x[04 ff]) and (0x[c0 ff ee] | bits rol 10 --signed --number-bytes 8 | bytes starts-with 0x[ff bb 03]) and (0x[ff bb 03] | bits ror 10 --number-bytes 8 | bytes starts-with 0x[c0 ff ee])'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-rotate-binary-bytes-fold"
        category: "language-core"
        tags: [aggregate list binary bits shl ror bytes collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (([0x[80] 0x[01 02]] | bits shl 1 | bytes collect | bytes length) == 3) and (([0x[80] 0x[01 02]] | bits ror 1 | bytes collect | bytes length) == 3)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-number-bytes"
        category: "language-core"
        tags: [aggregate list bits shl number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([127 128 -129] | bits shl 1 --number-bytes 1 | math sum) == 252'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-number-bytes-runtime"
        category: "language-core"
        tags: [aggregate list bits shl number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shl 1 --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-signed-fixed-runtime"
        category: "language-core"
        tags: [aggregate list bits shl signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shl 1 --signed --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-shift-unsigned-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits shr number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits shr 1 --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-signed-i64-runtime"
        category: "language-core"
        tags: [scalar bits shr signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits shr 1 --signed --number-bytes 8) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits shl number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits shl 1 --number-bytes 1) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-unsigned-i64-left-u32-runtime"
        category: "language-core"
        tags: [scalar bits shl number-bytes runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.pid | bits shl 1 --number-bytes 8) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-default"
        category: "language-core"
        tags: [scalar bits shl shr default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((128 | bits shl 1) == 0) and ((-129 | bits shr 1) == -65) and ((4294967296 | bits shl 1) == 8589934592)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-shift-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits shl default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl default auto-width shifts require compile-time known integer input"
    }
    {
        name: "core-scalar-bits-shift-unsigned-i64-runtime"
        category: "language-core"
        tags: [scalar bits shr number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits shr 1 --number-bytes 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-signed-i64"
        category: "language-core"
        tags: [scalar bits rol ror signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((1 | bits rol 1 --signed --number-bytes 8) == 2) and ((1 | bits ror 1 --signed --number-bytes 8) == -9223372036854775808) and ((1 | bits rol 64 --signed --number-bytes 8) == 1)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-i64"
        category: "language-core"
        tags: [aggregate list bits rol signed]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([4 3 2] | bits rol 1 --signed --number-bytes 8 | math sum) == 18'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-i64-runtime"
        category: "language-core"
        tags: [aggregate list bits ror signed runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --signed --number-bytes 8 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-number-bytes"
        category: "language-core"
        tags: [scalar bits rol ror signed number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((127 | bits rol 1 --number-bytes 1) == 254) and ((-65 | bits ror 1 --number-bytes 1) == -33) and ((1 | bits ror 32 --number-bytes 4) == 1) and ((1 | bits ror 1 --signed --number-bytes 1) == -128) and ((4294967296 | bits ror 1 --number-bytes 8) == 2147483648)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-number-bytes"
        category: "language-core"
        tags: [aggregate list bits rol number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([127 128 -129] | bits rol 1 --number-bytes 1 | math sum) == 253'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-number-bytes-runtime"
        category: "language-core"
        tags: [aggregate list bits ror number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-bits-rotate-signed-fixed-runtime"
        category: "language-core"
        tags: [aggregate list bits ror signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([(random int)] | bits ror 1 --signed --number-bytes 1 | length) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-signed-i64-runtime"
        category: "language-core"
        tags: [scalar bits rol signed number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits rol 1 --signed --number-bytes 8) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-number-bytes-runtime"
        category: "language-core"
        tags: [scalar bits ror number-bytes runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int | bits ror 1 --number-bytes 1) != 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-unsigned-i64-left-u32-runtime"
        category: "language-core"
        tags: [scalar bits rol number-bytes runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.pid | bits rol 1 --number-bytes 8) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default"
        category: "language-core"
        tags: [scalar bits rol ror default]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ((128 | bits rol 1) == 1) and ((-129 | bits rol 1) == -257) and ((4294967296 | bits ror 1) == 2147483648)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-bits-rotate-default-runtime-reject"
        category: "language-core"
        tags: [scalar bits rol default runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol default auto-width rotates require compile-time known integer input"
    }
    {
        name: "core-scalar-bits-rotate-unsigned-i64-runtime-reject"
        category: "language-core"
        tags: [scalar bits ror number-bytes runtime reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (random int) | bits ror 1 --number-bytes 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror unsigned --number-bytes 8 requires compile-time known integer input"
    }
    {
        name: "core-null-length"
        category: "language-core"
        tags: ["null" length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  null | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-length"
        category: "language-core"
        tags: [binary length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-length"
        category: "language-core"
        tags: [binary bytes length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-length-join"
        category: "language-core"
        tags: [binary list bytes length join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03] 0x[]] | bytes length | str join "-" | str starts-with "2-1-0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-starts-with"
        category: "language-core"
        tags: [binary bytes starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-ends-with"
        category: "language-core"
        tags: [binary bytes ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes ends-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-starts-with"
        category: "language-core"
        tags: [binary list bytes starts-with get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes starts-with 0x[03] | get 1) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-ends-with"
        category: "language-core"
        tags: [binary list bytes ends-with get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes ends-with 0x[02] | get 0) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of"
        category: "language-core"
        tags: [binary bytes index-of]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-end"
        category: "language-core"
        tags: [binary bytes index-of end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --end 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of"
        category: "language-core"
        tags: [binary list bytes index-of get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 02 02]] | bytes index-of 0x[02] | get 1) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-index-of-end"
        category: "language-core"
        tags: [binary list bytes index-of end get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[02 01 02] 0x[03 04]] | bytes index-of --end 0x[02] | get 0) == 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-all-join"
        category: "language-core"
        tags: [binary bytes index-of all join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --all 0x[02] | str join "-" | str starts-with "1-3"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-index-of-all-end-join"
        category: "language-core"
        tags: [binary bytes index-of all end join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 02] | bytes index-of --all --end 0x[02] | str join "-" | str starts-with "3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-reverse-starts-with"
        category: "language-core"
        tags: [binary bytes reverse starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03] | bytes reverse | bytes starts-with 0x[03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-reverse-empty-length"
        category: "language-core"
        tags: [binary bytes reverse empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes reverse | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse"
        category: "language-core"
        tags: [binary list bytes reverse get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ([0x[01 02] 0x[03 04]] | bytes reverse | get 0 | bytes starts-with 0x[02]) == 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes reverse empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes reverse unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-list-length"
        category: "language-core"
        tags: [binary list bytes reverse empty_list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-list-is-empty"
        category: "language-core"
        tags: [binary list bytes reverse empty_list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | bytes reverse | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-get"
        category: "language-core"
        tags: [binary list bytes reverse unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | get 1 | bytes starts-with 0x[03 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-get-length"
        category: "language-core"
        tags: [binary list bytes reverse empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-unequal-last"
        category: "language-core"
        tags: [binary list bytes reverse unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes reverse | last | bytes starts-with 0x[03 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-reverse-empty-first-length"
        category: "language-core"
        tags: [binary list bytes reverse empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes reverse | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-build-starts-with"
        category: "language-core"
        tags: [binary bytes build starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build 0x[01 02] 0x[03] 4 | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-build-empty-length"
        category: "language-core"
        tags: [binary bytes build empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bytes build | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-starts-with"
        category: "language-core"
        tags: [binary bytes at starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04] | bytes at 1..2 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-explicit-step-starts-with"
        category: "language-core"
        tags: [binary bytes at range step starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02 03 04 05 06] | bytes at 1..3..4 | bytes starts-with 0x[02 03 04 05]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-at-empty-length"
        category: "language-core"
        tags: [binary bytes at empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 02] | bytes at 1..0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-collect"
        category: "language-core"
        tags: [binary list bytes at collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01 02] 0x[03 04]] | bytes at 0..0 | bytes collect | bytes starts-with 0x[01 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes at empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0 | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes at unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2 | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-unequal-get"
        category: "language-core"
        tags: [binary list bytes at unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2 | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-empty-get-length"
        category: "language-core"
        tags: [binary list bytes at empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0 | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-unequal-last"
        category: "language-core"
        tags: [binary list bytes at unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes at 0..2 | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-at-empty-first-length"
        category: "language-core"
        tags: [binary list bytes at empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes at 1..0 | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-add-starts-with"
        category: "language-core"
        tags: [binary bytes add starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01 04] | bytes add 0x[02 03] --index 1 | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-add-empty-length"
        category: "language-core"
        tags: [binary bytes add empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes add 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-collect"
        category: "language-core"
        tags: [binary list bytes add collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bytes add 0x[ff] --index 1 | bytes collect | bytes starts-with 0x[01 ff 02 ff]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes add empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes add unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-unequal-get"
        category: "language-core"
        tags: [binary list bytes add unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[] | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-empty-get-length"
        category: "language-core"
        tags: [binary list bytes add empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-unequal-last"
        category: "language-core"
        tags: [binary list bytes add unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes add 0x[] | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-add-empty-first-length"
        category: "language-core"
        tags: [binary list bytes add empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[]] | bytes add 0x[] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-collect"
        category: "language-core"
        tags: [binary list bytes remove collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb]] | bytes remove 0x[10] | bytes collect | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes remove empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes remove unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10 20]] | bytes remove 0x[10] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-get"
        category: "language-core"
        tags: [binary list bytes remove unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | get 1 | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-get-length"
        category: "language-core"
        tags: [binary list bytes remove empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-unequal-last"
        category: "language-core"
        tags: [binary list bytes remove unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bytes remove 0x[ff] | last | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-remove-empty-first-length"
        category: "language-core"
        tags: [binary list bytes remove empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes remove 0x[10] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-collect"
        category: "language-core"
        tags: [binary list bytes replace collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb]] | bytes replace 0x[10] 0x[a0] | bytes collect | bytes starts-with 0x[a0 aa a0 bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-collect-length"
        category: "language-core"
        tags: [binary list bytes replace empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-collect-length"
        category: "language-core"
        tags: [binary list bytes replace unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-get"
        category: "language-core"
        tags: [binary list bytes replace unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | get 1 | bytes starts-with 0x[bb cc]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-get-length"
        category: "language-core"
        tags: [binary list bytes replace empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-unequal-last"
        category: "language-core"
        tags: [binary list bytes replace unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10 aa] 0x[10 bb cc]] | bytes replace 0x[10] 0x[] | last | bytes starts-with 0x[bb cc]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-bytes-replace-empty-first-length"
        category: "language-core"
        tags: [binary list bytes replace empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[10] 0x[10]] | bytes replace 0x[10] 0x[] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-starts-with"
        category: "language-core"
        tags: [binary bytes remove starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes remove --all 0x[10] | bytes starts-with 0x[aa bb]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-remove-empty-length"
        category: "language-core"
        tags: [binary bytes remove empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes remove 0x[10] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-replace-starts-with"
        category: "language-core"
        tags: [binary bytes replace starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10 aa 10 bb 10] | bytes replace --all 0x[10] 0x[a0] | bytes starts-with 0x[a0 aa a0]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-replace-empty-length"
        category: "language-core"
        tags: [binary bytes replace empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[10] | bytes replace 0x[10] 0x[] | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-starts-with"
        category: "language-core"
        tags: [binary bytes collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[11] 0x[33] 0x[44]] | bytes collect 0x[01] | bytes starts-with 0x[11 01 33]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-collect-empty-length"
        category: "language-core"
        tags: [binary bytes collect empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[]] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-sort-collect"
        category: "language-core"
        tags: [binary list sort bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[03] 0x[01] 0x[02]] | sort | bytes collect | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-length"
        category: "language-core"
        tags: [binary list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-is-empty"
        category: "language-core"
        tags: [binary list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-is-not-empty"
        category: "language-core"
        tags: [binary list is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-is-empty"
        category: "language-core"
        tags: [binary is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-is-not-empty"
        category: "language-core"
        tags: [binary is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | is-not-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-is-empty"
        category: "language-core"
        tags: [scalar int is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-scalar-is-not-empty"
        category: "language-core"
        tags: [scalar bool duration is-not-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (false | is-not-empty) and (0sec | is-not-empty)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-append-collect"
        category: "language-core"
        tags: [binary list append bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | append 0x[03] | bytes collect | bytes starts-with 0x[01 02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-prepend-collect"
        category: "language-core"
        tags: [binary list prepend bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | prepend 0x[00] | bytes collect | bytes starts-with 0x[00 01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-reverse-collect"
        category: "language-core"
        tags: [binary list reverse bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | reverse | bytes collect | bytes starts-with 0x[03 02 01]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-uniq-collect"
        category: "language-core"
        tags: [binary list uniq bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[01]] | uniq | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-find-collect"
        category: "language-core"
        tags: [binary list find bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03] 0x[02]] | find 0x[02] | bytes collect | bytes starts-with 0x[02 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-take-collect"
        category: "language-core"
        tags: [binary list take bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | take 2 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-skip-collect"
        category: "language-core"
        tags: [binary list skip bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | skip 1 | bytes collect | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-drop-collect"
        category: "language-core"
        tags: [binary list drop bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | drop 1 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-first-collect"
        category: "language-core"
        tags: [binary list first bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | first 2 | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-last-collect"
        category: "language-core"
        tags: [binary list last bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | last 2 | bytes collect | bytes starts-with 0x[02 03]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-get-starts-with"
        category: "language-core"
        tags: [binary list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02] 0x[03]] | get 1 | bytes starts-with 0x[02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-list-compact-collect"
        category: "language-core"
        tags: [binary list compact bytes collect]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[] 0x[02]] | compact --empty | bytes collect | bytes starts-with 0x[01 02]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-collect-starts-with"
        category: "language-core"
        tags: [binary bytes split collect starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 2d 2d 63] | bytes split "--" | bytes collect 0x[20] | bytes starts-with 0x[61 20 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-part-collect-length"
        category: "language-core"
        tags: [binary bytes split empty collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-collect-length"
        category: "language-core"
        tags: [binary bytes split unequal collect length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | bytes collect | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-get"
        category: "language-core"
        tags: [binary bytes split unequal get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | get 1 | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-get-length"
        category: "language-core"
        tags: [binary bytes split empty get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | get 0 | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-unequal-last"
        category: "language-core"
        tags: [binary bytes split unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 20 62 62] | bytes split 0x[20] | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-first-length"
        category: "language-core"
        tags: [binary bytes split empty first length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[20 61] | bytes split 0x[20] | first | bytes length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-string-separator-unequal-last"
        category: "language-core"
        tags: [binary bytes split string separator unequal last starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[61 2d 2d 62 62] | bytes split "--" | last | bytes starts-with 0x[62 62]'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-binary-bytes-split-empty-input-length"
        category: "language-core"
        tags: [binary bytes split empty length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bytes split 0x[20] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-is-empty"
        category: "language-core"
        tags: [string is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "" | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length"
        category: "language-core"
        tags: [string str length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-grapheme-clusters"
        category: "language-core"
        tags: [string str length grapheme-clusters]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "🇯🇵ほげ" | str length --grapheme-clusters'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-length-chars"
        category: "language-core"
        tags: [string str length chars]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ("Amélie" | str length --chars) == 7'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-sum"
        category: "language-core"
        tags: [string list str length sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "bb"] | str length | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-grapheme-clusters-sum"
        category: "language-core"
        tags: [string list str length grapheme-clusters sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["🇯🇵" "ほげ"] | str length --grapheme-clusters | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-str-length-chars-sum"
        category: "language-core"
        tags: [string list str length chars sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (["Amélie" "字"] | str length --chars | math sum) == 8'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-too-long"
        category: "language-core"
        tags: [string str starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str starts-with "abcdefghijklmnopqrstu"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-starts-with-tracked-length"
        category: "language-core"
        tags: [string str starts-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with "hello"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-starts-with-ignore-case"
        category: "language-core"
        tags: [string str starts-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str starts-with --ignore-case "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-starts-with-join"
        category: "language-core"
        tags: [string list str starts-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "xbc"] | str starts-with "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str ends-with "def"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-too-long"
        category: "language-core"
        tags: [string str ends-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a" | str ends-with "abcdef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-ends-with-tracked-length"
        category: "language-core"
        tags: [string str ends-with runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with "lo"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-ends-with-ignore-case"
        category: "language-core"
        tags: [string str ends-with ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str ends-with --ignore-case "CD"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-ends-with-join"
        category: "language-core"
        tags: [string list str ends-with join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "abx"] | str ends-with "c" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-string-contains-tracked-length"
        category: "language-core"
        tags: [string str contains runtime globals]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains "ll"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-join"
        category: "language-core"
        tags: [string list str contains join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" "def"] | str contains "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-contains-ignore-case-join"
        category: "language-core"
        tags: [string list str contains ignore-case join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["Abc" "def"] | str contains --ignore-case "a" | str join "-" | str starts-with "true-false"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-missing"
        category: "language-core"
        tags: [string str contains]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcdef" | str contains "zz"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-contains-ignore-case"
        category: "language-core"
        tags: [string str contains ignore-case]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbCd" | str contains --ignore-case "bc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-distance"
        category: "language-core"
        tags: [string str distance]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nushell" | str distance "nutshell"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-join-scalar"
        category: "language-core"
        tags: [string str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str join "-" | str starts-with "abc"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-join"
        category: "language-core"
        tags: [string list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-scalar-list-join"
        category: "language-core"
        tags: [string list scalar str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 1.5 1kb 1sec 0x[01 02] true null] | str join ":" | str starts-with "1:1.5:1.0 kB:1sec:[1, 2]:true:"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-aggregate-list-join"
        category: "language-core"
        tags: [string list aggregate record str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let records = ([{a: 1 b: 2} {c: 3}] | str join ":")'
            '  let lists = ([[1 2] [3]] | str join ":")'
            '  (($records | str starts-with "{a: 1") and ($records | str contains "b: 2}:{c: 3}")) and (($lists | str starts-with "[1") and ($lists | str contains "2]:[3]"))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-fill-right"
        category: "language-core"
        tags: [string fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab" | fill --alignment right --character "0" --width 5 | str starts-with "000ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-int-fill-right"
        category: "language-core"
        tags: [int fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  42 | fill --alignment right --character "0" --width 5 | str starts-with "00042"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-runtime-unsigned-int-fill"
        category: "language-core"
        tags: [int runtime fill context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | fill | str starts-with "0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-float-fill-right"
        category: "language-core"
        tags: [float fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1.25 | fill --alignment right --character "0" --width 6 | str starts-with "001.25"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-filesize-fill-right"
        category: "language-core"
        tags: [filesize fill right]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1kb | fill --alignment right --character "_" --width 8 | str starts-with "____1000"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-named-prompt"
        category: "language-core"
        tags: [string char named]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char prompt | str starts-with "▶"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-named-extra-string-args"
        category: "language-core"
        tags: [string char named rest]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char prompt ignored 1f354 | str starts-with "▶"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-unicode-codepoints"
        category: "language-core"
        tags: [string char unicode]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --unicode 1F468 200D 1F466 | str starts-with "👨‍👦"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-char-integer-codepoints"
        category: "language-core"
        tags: [string char integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  char --integer 65 66 | str starts-with "AB"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "core-list-split-list-string-group-join"
        category: "language-core"
        tags: [list split-list string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x" "c" "d" "x" "e" "f"] | split list "x" | get 1 | str join "-" | str starts-with "c-d"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-after-string-group-join"
        category: "language-core"
        tags: [list split-list after string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x" "c" "x" "e" "f"] | split list --split after "x" | get 1 | str join "-" | str starts-with "c-x"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-before-string-group-join"
        category: "language-core"
        tags: [list split-list before string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b" "x" "c" "x" "d"] | split list --split before "x" | get 1 | str join "-" | str starts-with "x-c"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-regex-after-string-group-join"
        category: "language-core"
        tags: [list split-list regex after string join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x1" "c" "x22" "e" "f"] | split list --regex --split after "x\\d+" | get 1 | str join "-" | str starts-with "c-x22"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-split-list-heterogeneous-materialized-reject"
        category: "language-core"
        tags: [aggregate list split-list reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "x" "b" "c" "x" "d"] | split list "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "split list result requires homogeneous fixed-layout groups"
    }
    {
        name: "core-string-split-chars-join"
        category: "language-core"
        tags: [string split chars join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b" | split chars | str join "-" | str starts-with "a-🇯-🇵-b"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-chars-grapheme-join"
        category: "language-core"
        tags: [string split chars grapheme join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a🇯🇵b" | split chars --grapheme-clusters | str join "-" | str starts-with "a-🇯🇵-b"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-words-join"
        category: "language-core"
        tags: [string split words join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello, to the world!" | split words | str join "-" | str starts-with "hello-to-the-world"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-words-min-utf8-join"
        category: "language-core"
        tags: [string split words min utf8 join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "a é ee" | split words --min-word-length 2 --utf-8-bytes | str join "-" | str starts-with "é-ee"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-nested-metadata"
        category: "language-core"
        tags: [string list split chars words nested join length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let chars = (["ab" "cd"] | split chars | str join ":")'
            '  let words = (["a b" "c d e"] | split words | str join ":")'
            '  (($chars | str starts-with "[a") and ($chars | str contains "b]:[c")) and ((($words | str starts-with "[a") and ($words | str contains "e]")) and ((["ab" "cd"] | split chars | length) == 2))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-split-row-join"
        category: "language-core"
        tags: [string split row join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "alpha,beta,gamma" | split row "," | str join "-" | str starts-with "alpha-beta-gamma"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-row-number-join"
        category: "language-core"
        tags: [string list split row number join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a,b,c" "d,e"] | split row "," --number 2 | str join "-" | str starts-with "a-b,c-d-e"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-split-row-regex-number-join"
        category: "language-core"
        tags: [string list split row regex number join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a1b2c" "d33e"] | split row --regex "\\d+" --number 2 | str join "-" | str starts-with "a-b2c-d-e"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-get-field"
        category: "language-core"
        tags: [string str stats record get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "Amélie Amelie" | str stats | get bytes'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-stats-unicode-width-get-field"
        category: "language-core"
        tags: [string str stats record get unicode-width]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "字\r\n字" | str stats | get unicode-width'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-length"
        category: "language-core"
        tags: [string str expand list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-path-length"
        category: "language-core"
        tags: [string str expand list length path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "C:\\{Users,Windows}" | str expand --path | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-empty-length"
        category: "language-core"
        tags: [string str expand list length empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{2..1}B" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-length"
        category: "language-core"
        tags: [string str expand list get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 0 | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 1 | str starts-with "AbDfG"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-range-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{08..10}B" | str expand | get 2 | str starts-with "A10B"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
