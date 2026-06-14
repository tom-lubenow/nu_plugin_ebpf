const VERIFIER_DIFF_FIXTURES_0657_0687_B = [
    {
        name: "tc-packet-header-alias-write"
        category: "context-surface"
        tags: [tc context packet writable packet-header alias source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.h_proto = 0x86dd'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-phi-joined-packet-data-read"
        category: "context-surface"
        tags: [tc context packet phi accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let selector = $ctx.mark'
            '  let data = (if $selector == 0 { $ctx.data } else { $ctx.data })'
            '  if ($ctx.data_end != 0) {'
            '    ($data | get 0) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: ($ctx | get data) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-identity-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record identity-wrapper get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  mut rec = { data: (id ($ctx | get data)) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-spread-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record spread source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable user-function record source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  let data = $ctx.data'
            '  mut rec = (wrap $data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: $ctx.data_meta }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: ($ctx | get data_meta) }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-pipeline-upsert-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record pipeline upsert get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert meta ($ctx | get data_meta))'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-bound-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable alias get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut meta = ($ctx | get data_meta)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-spread-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record spread source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let base = { meta: $ctx.data_meta }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-user-function-record-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable user-function record source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def wrap [meta] { { meta: $meta } }'
            '  let meta = $ctx.data_meta'
            '  mut rec = (wrap $meta)'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-user-function-returned-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable user-function alias source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event.data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-user-function-returned-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable user-function alias get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event | get data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-egress-rejects-context-socket-write"
        category: "context-policy"
        tags: [tc context writable socket reject egress-only]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs"
    }
]
