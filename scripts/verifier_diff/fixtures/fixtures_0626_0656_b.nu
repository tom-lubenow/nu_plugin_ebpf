const VERIFIER_DIFF_FIXTURES_0626_0656_B = [
    {
        name: "tc-record-pipeline-insert-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline insert get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | insert socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-rename-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline rename get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: ($ctx | get sk) } | rename sock)'
            '  $rec | get sock | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-merge-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline merge get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | merge { socket: ($ctx | get sk) })'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-default-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline default get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default ($ctx | get sk) socket)'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-update-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline update get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk } | update socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-scalar"
        category: "context-surface"
        tags: [tc context get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get packet_len | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-packet-data-read"
        category: "context-surface"
        tags: [tc context packet get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get data | get 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-socket-chain"
        category: "context-surface"
        tags: [tc context socket get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-socket-bound-root"
        category: "context-surface"
        tags: [tc context socket get alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = ($ctx | get sk)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-context-get-root"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx | get sk) }'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-context-get-root"
        category: "context-surface"
        tags: [tc context socket user-function get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [c] { $c | get sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-context-get-root"
        category: "context-surface"
        tags: [tc context socket record user-function get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [c] { { socket: ($c | get sk) } }'
            '  wrap $ctx | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-context-get-scalar"
        category: "context-surface"
        tags: [tc context user-function get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_packet [event] {'
            '    $event | get packet_len | count'
            '    0'
            '  }'
            '  read_packet $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-context-get-bound-socket"
        category: "context-surface"
        tags: [tc context socket user-function get alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [event] {'
            '    let sk = ($event | get sk)'
            '    $sk | get family | count'
            '    0'
            '  }'
            '  read_family $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-spread-write"
        category: "context-surface"
        tags: [tc-action context packet writable record spread source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-user-function-record-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable record user-function source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
