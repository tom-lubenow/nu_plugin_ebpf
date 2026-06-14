const VERIFIER_DIFF_FIXTURES_0657_0687_A = [
    {
        name: "tc-action-context-socket-write"
        category: "context-surface"
        tags: [tc-action context writable socket source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-socket-write"
        category: "context-surface"
        tags: [tc-action context writable socket record source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sk = 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-helper-backed-socket-projections"
        category: "context-surface"
        tags: [tc context socket helper-backed]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  ($ctx.sk.tcp.snd_cwnd + $ctx.sk.full.family + $ctx.sk.listener.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-bound-socket-projection"
        category: "context-surface"
        tags: [tc context socket user-function source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [sk] {'
            '    $sk.family | count'
            '    0'
            '  }'
            '  let sk = $ctx.sk'
            '  let seen = (read_family $sk)'
            '  $seen | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-ingress-skb-context-write"
        category: "context-surface"
        tags: [tc context packet writable]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable alias source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable alias get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = ($ctx | get data)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-upsert-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline upsert get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-insert-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline insert get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-merge-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline merge get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { data: ($ctx | get data) })'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-default-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline default get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get data) data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-update-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline update get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: null } | update data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-select-reject-rename-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline select reject rename get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: ($ctx | get data), keep: 1 } | select data keep | reject keep | rename packet)'
            '  $rec.packet.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable user-function alias source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event.data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable user-function alias get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event | get data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
