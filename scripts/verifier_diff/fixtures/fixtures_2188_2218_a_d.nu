const VERIFIER_DIFF_FIXTURES_2188_2218_A_D = [
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
