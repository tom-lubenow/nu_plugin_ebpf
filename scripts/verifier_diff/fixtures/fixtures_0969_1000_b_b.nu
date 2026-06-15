const VERIFIER_DIFF_FIXTURES_0969_1000_B_B = [
    {
        name: "sk-reuseport-select-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.hash + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-packet-context"
        category: "context-surface"
        tags: [sk-reuseport context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-rich-context"
        category: "context-surface"
        tags: [sk-reuseport context packet socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.type + $ctx.sk.protocol + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let rec = { sock: $ctx.sk }'
            '  ($rec.sock.family + $ctx.hash) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-spread-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record spread source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let base = { sock: $ctx.sock }'
            '  let rec = { ok: true, ...$base }'
            '  ($rec.sock.priority + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-user-function-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket user-function record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { sock: $sock } }'
            '  let rec = (wrap $ctx.sk)'
            '  ($rec.sock.rx_queue_mapping + $ctx.bind_inany) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrate-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie + $ctx.sk.bound_dev_if + $ctx.migrating_sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrating-socket-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let migrating = $ctx.migrating_socket'
            '  if $migrating {'
            '    $migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-migrating-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let rec = { migrating: $ctx.migrating_socket }'
            '  if $rec.migrating {'
            '    $rec.migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-migrating-sk-nullable-context"
        category: "context-surface"
        tags: [sk-reuseport context socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  if $ctx.migrating_sk {'
            '    $ctx.migrating_sk.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
