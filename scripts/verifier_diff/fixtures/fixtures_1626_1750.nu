const VERIFIER_DIFF_FIXTURES_1626_1750 = [
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
        error_contains: "first requires a non-empty stack-backed numeric list"
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
        error_contains: "last requires a non-empty stack-backed numeric list"
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
    {
        name: "core-list-first-negative-count-reject"
        category: "language-core"
        tags: [aggregate list first reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | first -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "first count must be non-negative"
    }
    {
        name: "core-list-last-negative-count-reject"
        category: "language-core"
        tags: [aggregate list last reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | last -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "last count must be non-negative"
    }
    {
        name: "core-list-get-negative-index-reject"
        category: "language-core"
        tags: [aggregate list get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let i = -1'
            '  [10 20 30] | get $i'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index must be non-negative"
    }
    {
        name: "core-list-get-out-of-bounds-reject"
        category: "language-core"
        tags: [aggregate list get reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | get 3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "get index 3 is out of bounds"
    }
    {
        name: "core-list-take-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 2 | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-oversized-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 4 | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-zero-count"
        category: "language-core"
        tags: [aggregate list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 0 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-take-negative-count-reject"
        category: "language-core"
        tags: [aggregate list take reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "take count must be non-negative"
    }
    {
        name: "core-list-reverse"
        category: "language-core"
        tags: [aggregate list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-reverse-after-take"
        category: "language-core"
        tags: [aggregate list reverse take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | take 2 | reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-uniq"
        category: "language-core"
        tags: [aggregate list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 10 30 20] | uniq | get 2'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-uniq-empty"
        category: "language-core"
        tags: [aggregate list uniq empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | uniq | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort"
        category: "language-core"
        tags: [aggregate list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [30 10 20] | sort | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort-reverse"
        category: "language-core"
        tags: [aggregate list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 30 20] | sort --reverse | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-sort-capacity-reject"
        category: "language-core"
        tags: [aggregate list sort reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 16 | sort | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sort supports stack-backed numeric lists with capacity <= 16"
    }
    {
        name: "core-list-compact"
        category: "language-core"
        tags: [aggregate list compact]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-compact-empty"
        category: "language-core"
        tags: [aggregate list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact --empty | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-compact-column-reject"
        category: "language-core"
        tags: [aggregate list compact reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | compact value'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "compact does not accept column arguments"
    }
    {
        name: "core-record-list-compact-column-length"
        category: "language-core"
        tags: [aggregate record list compact column length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 8 } { pid: 9 cpu: 4 }] | compact cpu | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-record-list-compact-empty-column-length"
        category: "language-core"
        tags: [aggregate record list compact empty column length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [{ pid: 7 comm: "" } { pid: 8 comm: "nu" } { pid: 9 }] | compact --empty comm | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find"
        category: "language-core"
        tags: [aggregate list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | find 20 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-find-missing"
        category: "language-core"
        tags: [aggregate list find empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | find 99 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-default"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-zero-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 0 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-oversized-count"
        category: "language-core"
        tags: [aggregate list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop 4 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-drop-negative-count-reject"
        category: "language-core"
        tags: [aggregate list drop reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | drop -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "drop count must be non-negative"
    }
    {
        name: "core-list-skip-default"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-count"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip 2 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-oversized-count"
        category: "language-core"
        tags: [aggregate list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip 4 | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-skip-negative-count-reject"
        category: "language-core"
        tags: [aggregate list skip reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | skip -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "skip count must be non-negative"
    }
    {
        name: "core-list-append"
        category: "language-core"
        tags: [aggregate list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | append 40 | get 3'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-prepend"
        category: "language-core"
        tags: [aggregate list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | prepend 5 | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-each"
        category: "language-core"
        tags: [aggregate list each closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | each {|x| $x + 1 } | get 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-where"
        category: "language-core"
        tags: [aggregate list where closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | where {|x| $x > 15 } | get 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any"
        category: "language-core"
        tags: [aggregate list any closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all"
        category: "language-core"
        tags: [aggregate list all closure]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | all {|x| $x > 5 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-any-empty"
        category: "language-core"
        tags: [aggregate list any closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | any {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-all-empty"
        category: "language-core"
        tags: [aggregate list all closure empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | all {|x| $x > 15 }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-append-capacity-reject"
        category: "language-core"
        tags: [aggregate list append reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 0 59 | append 60 | get 60'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "append would exceed stack-backed numeric list capacity 60"
    }
    {
        name: "core-list-is-empty"
        category: "language-core"
        tags: [aggregate list is-empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [] | is-empty'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-length"
        category: "language-core"
        tags: [aggregate list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-length"
        category: "language-core"
        tags: [string list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-get"
        category: "language-core"
        tags: [string list get]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | get 1 | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | first | str starts-with "ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | last | str starts-with "cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-take"
        category: "language-core"
        tags: [string list take]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | take 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-skip"
        category: "language-core"
        tags: [string list skip]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | skip 1 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-drop"
        category: "language-core"
        tags: [string list drop]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | drop 1 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-first-count"
        category: "language-core"
        tags: [string list first]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | first 2 | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-last-count"
        category: "language-core"
        tags: [string list last]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | last 2 | str join "-" | str starts-with "cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-reverse"
        category: "language-core"
        tags: [string list reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef"] | reverse | str join "-" | str starts-with "ef-cd-ab"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-append"
        category: "language-core"
        tags: [string list append]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | append "ef" | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-prepend"
        category: "language-core"
        tags: [string list prepend]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd"] | prepend "zz" | str join "-" | str starts-with "zz-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-uniq"
        category: "language-core"
        tags: [string list uniq]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ab" "ef" "cd"] | uniq | str join "-" | str starts-with "ab-cd-ef"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort"
        category: "language-core"
        tags: [string list sort]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort | str join "-" | str starts-with "aa-ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-sort-reverse"
        category: "language-core"
        tags: [string list sort reverse]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["cd" "aa" "ab"] | sort --reverse | str join "-" | str starts-with "cd-ab-aa"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-find"
        category: "language-core"
        tags: [string list find]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "cd" "ef" "cd"] | find "cd" | str join "-" | str starts-with "cd-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-list-compact-empty"
        category: "language-core"
        tags: [string list compact empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" "" "cd"] | compact --empty | str join "-" | str starts-with "ab-cd"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-sum"
        category: "language-core"
        tags: [aggregate list math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-integer-sum"
        category: "language-core"
        tags: [aggregate list seq math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 5 | math sum) == 15'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-negative-step-join"
        category: "language-core"
        tags: [aggregate list seq str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 5 -2 1 | str join "-" | str starts-with "5-3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-float-join"
        category: "language-core"
        tags: [aggregate list seq float str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1.0 0.5 2.0 | str join "," | str starts-with "1.0,1.5,2.0"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-float-metadata-transforms"
        category: "language-core"
        tags: [aggregate list seq float sort reverse find split-list str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let sort_ok = (seq 2.0 -0.5 1.0 | sort | str join "," | str starts-with "1.0,1.5,2.0")'
            '  let reverse_ok = (seq 1.0 0.5 2.0 | reverse | str join "," | str starts-with "2.0,1.5,1.0")'
            '  $sort_ok and ($reverse_ok and (((seq 1.0 0.5 2.0 | find 1.5 | length) == 1) and ((seq 1.0 0.5 2.0 | split list 1.5 | length) == 2)))'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-char-join"
        category: "language-core"
        tags: [aggregate list seq char str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char e a | str join "-" | str starts-with "e-d-c-b-a"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-char-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq char reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char A ~ | str join ""'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq char output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-seq-date-join"
        category: "language-core"
        tags: [aggregate list seq date str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-05" --increment 2 | str join "," | str starts-with "2020-01-01,2020-01-03,2020-01-05"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-length"
        category: "language-core"
        tags: [aggregate list seq date length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq date --begin-date "2020-01-05" --end-date "2020-01-01" | length) == 5'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-days-join"
        category: "language-core"
        tags: [aggregate list seq date days str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --days 5 --increment 2 | str join "," | str starts-with "2020-01-01,2020-01-03,2020-01-05"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-periods-join"
        category: "language-core"
        tags: [aggregate list seq date periods str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 4 --increment 3 | str join "," | str starts-with "2020-01-01,2020-01-04,2020-01-07,2020-01-10"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-format-join"
        category: "language-core"
        tags: [aggregate list seq date format str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --input-format "%m/%d/%Y" --output-format "%Y/%m/%d" --begin-date "01/01/2020" --end-date "01/03/2020" | str join "," | str starts-with "2020/01/01,2020/01/02,2020/01/03"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-duration-increment-join"
        category: "language-core"
        tags: [aggregate list seq date duration increment str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-02" --increment 6hr --output-format "%Y-%m-%d %H:%M:%S" | str join "," | str starts-with "2020-01-01 00:00:00,2020-01-01 06:00:00,2020-01-01 12:00:00,2020-01-01 18:00:00,2020-01-02 00:00:00"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-reverse-periods-join"
        category: "language-core"
        tags: [aggregate list seq date reverse periods str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 3 --increment 2 --reverse | str join "," | str starts-with "2020-01-01,2019-12-30,2019-12-28,2019-12-26,2019-12-24"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-date-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq date reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-03-15" | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-seq-date-periods-over-capacity-reject"
        category: "language-core"
        tags: [aggregate list seq date periods reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --periods 61 | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date output exceeds fixed string-list capacity 60"
    }
    {
        name: "core-list-math-product"
        category: "language-core"
        tags: [aggregate list math product]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2 3 4] | math product'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-max"
        category: "language-core"
        tags: [aggregate list math max]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math max'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
