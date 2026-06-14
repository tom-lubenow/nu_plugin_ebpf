const VERIFIER_DIFF_FIXTURES_2188_2218_A = [
    {
        name: "core-context-redirect-rejects-pointer-ifindex"
        category: "language-core"
        tags: [context redirect reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | redirect'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-socket-rejects-pointer-key"
        category: "language-core"
        tags: [context redirect-socket reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx | redirect-socket peers --kind sockmap'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-assign-socket-rejects-pointer-socket"
        category: "language-core"
        tags: [context assign-socket reject]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx | assign-socket --replace'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-random-int-rejects-pipeline-input"
        category: "language-core"
        tags: [random reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | random int'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-define-rejects-pipeline-input"
        category: "language-core"
        tags: [maps map-define reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-define seen --kind hash --key-type u64 --value-type u64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-start-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | start-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-stop-timer-rejects-pipeline-input"
        category: "language-core"
        tags: [timer reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | stop-timer'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-timer-allows-after-prior-statement"
        category: "language-core"
        tags: [timer accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  start-timer'
            '  stop-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-map-put-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-put reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put requires a value from pipeline input"
    }
    {
        name: "core-map-push-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [maps map-push reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  map-push recent --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-push requires a value from pipeline input"
    }
    {
        name: "core-global-set-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-set requires a value from pipeline input"
    }
    {
        name: "core-global-define-rejects-prior-statement-as-value"
        category: "language-core"
        tags: [global reject pipeline]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  99'
            '  global-define state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "global-define requires a compile-time constant value from pipeline input"
    }
    {
        name: "core-map-peek-rejects-pipeline-input"
        category: "language-core"
        tags: [maps queue map-peek reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = ($ctx | map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-map-pop-rejects-pipeline-input"
        category: "language-core"
        tags: [maps stack map-pop reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = ($ctx | map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "does not accept pipeline input"
    }
    {
        name: "core-context-map-get-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-get seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
]
