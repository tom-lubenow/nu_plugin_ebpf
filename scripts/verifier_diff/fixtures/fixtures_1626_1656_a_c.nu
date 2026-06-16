const VERIFIER_DIFF_FIXTURES_1626_1656_A_C = [
    {
        name: "core-early-return"
        category: "language-core"
        tags: [control-flow return]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  if true { return 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-early-return"
        category: "language-core"
        tags: [control-flow return user-function]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def choose [x] {'
            '    if $x == 0 { return 7 }'
            '    9'
            '  }'
            '  choose 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-user-function-named-argument-and-switch"
        category: "language-core"
        tags: [control-flow user-function named switch accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def choose [x: int --amount: int --enabled] {'
            '    if $enabled { $x + $amount } else { $x }'
            '  }'
            '  let on = (choose $ctx.pid --amount 1 --enabled)'
            '  let off = (choose $ctx.pid --amount 2)'
            '  $on >= $off'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
