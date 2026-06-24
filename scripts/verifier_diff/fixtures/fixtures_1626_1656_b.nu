const VERIFIER_DIFF_FIXTURES_1626_1656_B = [
    {
        name: "core-loop-break-continue"
        category: "language-core"
        tags: [control-flow loop break continue]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for i in 0..3 {'
            '    if $i == 1 { continue }'
            '    if $i == 3 { break }'
            '    $sum = ($sum + $i)'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-loop-early-return"
        category: "language-core"
        tags: [control-flow loop return]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut seen = 0'
            '  for i in 0..3 {'
            '    if $i == 2 { return $i }'
            '    $seen = $i'
            '  }'
            '  $seen'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-nested-loop-break-continue"
        category: "language-core"
        tags: [control-flow loop break continue]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for i in 0..2 {'
            '    for j in 0..2 {'
            '      if $j == 1 { continue }'
            '      if $i == 2 { break }'
            '      $sum = ($sum + $i + $j)'
            '    }'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-dynamic-range-loop-reject"
        category: "language-core"
        tags: [control-flow loop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let end = $ctx.pid'
            '  for i in 0..$end {'
            '    $i | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Range end must be a compile-time known integer for eBPF loops"
    }
    {
        name: "core-dynamic-bounded-range-loop"
        category: "language-core"
        tags: [control-flow loop range runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = (random int | bits and 3)'
            '  mut sum = 0'
            '  for i in 1..$n {'
            '    $sum = ($sum + $i)'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-literal-list-iterate"
        category: "language-core"
        tags: [control-flow loop aggregate list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for item in [10 20 30] {'
            '    $sum = ($sum + $item)'
            '  }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-inline-bounded-loop"
        category: "language-core"
        tags: [control-flow loop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  if true { for i in 0..3 { $sum = ($sum + $i) } }'
            '  $sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-bounded-loop"
        category: "language-core"
        tags: [control-flow loop user-function]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def sum [] {'
            '    mut total = 0'
            '    for i in 0..3 {'
            '      $total = ($total + $i)'
            '    }'
            '    $total'
            '  }'
            '  sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-list-iterate"
        category: "language-core"
        tags: [control-flow loop aggregate list user-function]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def sum_list [] {'
            '    mut sum = 0'
            '    for item in [10 20 30] {'
            '      $sum = ($sum + $item)'
            '    }'
            '    $sum'
            '  }'
            '  sum_list'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
