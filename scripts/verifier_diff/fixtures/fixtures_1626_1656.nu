const VERIFIER_DIFF_FIXTURES_1626_1656 = [
    {
        name: "csum-diff-rejects-null-dynamic-side"
        category: "helper-state"
        tags: [csum null-pointer dynamic reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let size = ((helper-call "bpf_get_prandom_u32") + 4)'
            '  helper-call "bpf_csum_diff" 0 $size 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "csum-diff-rejects-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 2 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "csum-diff-rejects-dynamic-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy dynamic branch reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let size = (if $selector == 0 { 0 } else { 2 })'
            '  helper-call "bpf_csum_diff" 0 $size 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "redirect-neigh-allows-null-params"
        category: "helper-state"
        tags: [redirect-neigh null-pointer tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 0 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-neigh-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-neigh flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_neigh" 1 0 0 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg3 = 0"
    }
    {
        name: "redirect-neigh-rejects-null-nonzero-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 4 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "redirect-neigh-rejects-null-dynamic-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer dynamic reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let plen = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_neigh" 1 0 $plen 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "redirect-peer-helper"
        category: "helper-state"
        tags: [redirect-peer tc-action accept source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_peer" 1 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-peer-rejects-nonzero-flags"
        category: "helper-state"
        tags: [redirect-peer flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_peer" 1 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
    {
        name: "redirect-helper-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect flags reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect" 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect' requires arg1 flags to contain only BPF_F_INGRESS"
    }
    {
        name: "clone-redirect-rejects-dynamic-flags"
        category: "helper-state"
        tags: [clone-redirect flags reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_clone_redirect" $ctx 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skb/message redirect helpers require flags to contain only BPF_F_INGRESS"
    }
    {
        name: "redirect-map-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-map flags reject xdp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_map" tx_ports 0 $flags --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_map' requires arg2 flags"
    }
    {
        name: "redirect-peer-rejects-dynamic-flags"
        category: "helper-state"
        tags: [redirect-peer flags reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_redirect_peer" 1 $flags'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' requires arg1 = 0"
    }
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
    {
        name: "core-null-compare-flow"
        category: "language-core"
        tags: [control-flow "null"]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let maybe = null'
            '  if $maybe == null { 1 } else { 0 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-spread"
        category: "language-core"
        tags: [aggregate list spread]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let xs = [1, 2]'
            '  let ys = [0, ...$xs, 3]'
            '  $ys | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-scalar"
        category: "language-core"
        tags: [aggregate list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-scalar"
        category: "language-core"
        tags: [aggregate list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-first-empty-reject"
        category: "language-core"
        tags: [aggregate list first reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | first'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first requires a stack-backed numeric list with proven non-empty length"
    }
    {
        name: "core-list-last-empty-reject"
        category: "language-core"
        tags: [aggregate list last reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | last'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last requires a stack-backed numeric list with proven non-empty length"
    }
    {
        name: "core-list-first-count"
        category: "language-core"
        tags: [aggregate list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first 2 | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-last-count"
        category: "language-core"
        tags: [aggregate list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
