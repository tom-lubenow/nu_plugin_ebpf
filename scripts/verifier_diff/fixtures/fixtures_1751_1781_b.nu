const VERIFIER_DIFF_FIXTURES_1751_1781_B = [
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
]
