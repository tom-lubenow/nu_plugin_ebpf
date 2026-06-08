const VERIFIER_DIFF_FIXTURES_0626_0750 = [
    {
        name: "xdp-cgroup-array-contains"
        category: "packet"
        tags: [xdp cgroup-array helper-policy]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context"
        category: "context-surface"
        tags: [tc-action context packet]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-rich-metadata-context"
        category: "context-surface"
        tags: [tc-action context packet source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.wire_len + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.tstamp + $ctx.tstamp_type + $ctx.hwtstamp + $ctx.cb.0) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable record source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-upsert-write"
        category: "context-surface"
        tags: [tc-action context packet writable record upsert source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-upsert"
        category: "context-surface"
        tags: [tc context socket record upsert source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | upsert socket $ctx.sk)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-preserve"
        category: "context-surface"
        tags: [tc context socket record upsert preserve source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ($base | upsert ok true)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-shape"
        category: "context-surface"
        tags: [tc context socket record merge select reject rename source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk, keep: 1 } | merge { ok: true } | select socket ok | reject ok | rename sock)'
            '  $rec.sock.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-default-field"
        category: "context-surface"
        tags: [tc context socket record default source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default $ctx.sk socket)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-spread-pipeline-rename"
        category: "context-surface"
        tags: [tc context socket record spread rename source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ({ ...$base } | rename sock)'
            '  $rec.sock.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-get-root"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  let sk = ($rec | get socket)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-get-chain"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-rename-get-chain"
        category: "context-surface"
        tags: [tc context socket record rename get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { ok: true, socket: $ctx.sk }'
            '  $rec | rename keep sock | get sock | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-wrapper-get-chain"
        category: "context-surface"
        tags: [tc context socket record wrapper get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { socket: $sock } }'
            '  wrap $ctx.sk | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
    {
        name: "tc-skb-get-xfrm-state-helper"
        category: "helper-state"
        tags: [tc helper xfrm accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-get-xfrm-state-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper xfrm flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"
    }
    {
        name: "tc-skb-vlan-push-helper"
        category: "helper-state"
        tags: [tc helper vlan accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-vlan-pop-helper"
        category: "helper-state"
        tags: [tc helper vlan accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_pop" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-vlan-push-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper vlan packet-bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-vlan-push-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper vlan packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-proto-helper"
        category: "helper-state"
        tags: [tc helper skb-change accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-proto-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_proto' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-proto-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_proto' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-tail-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper skb-change packet-bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_skb_change_tail" $ctx 64 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-change-tail-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper skb-change packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_tail" $ctx 64 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-tail-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_tail" $ctx 64 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_tail' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-head-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_head" $ctx 14 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_head' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-head-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_head" $ctx 14 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_head' requires arg2 = 0"
    }
    {
        name: "tc-skb-adjust-room-helper"
        category: "helper-state"
        tags: [tc helper skb-change accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_adjust_room" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-adjust-room-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_adjust_room" $ctx 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg3 flags"
    }
    {
        name: "tc-skb-change-type-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_type" $ctx 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-ecn-set-ce-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_ecn_set_ce" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tstamp-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tstamp-rejects-invalid-type"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg2"
    }
    {
        name: "tc-skb-set-tstamp-rejects-dynamic-type"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let tstype = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 $tstype'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg2"
    }
    {
        name: "tc-skb-set-tstamp-rejects-unspec-nonzero-tstamp"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
    }
    {
        name: "tc-skb-set-tstamp-rejects-unspec-dynamic-tstamp"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let tstamp = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_set_tstamp" $ctx $tstamp 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
    }
    {
        name: "tc-skb-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let bytes = "x"'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-store-bytes-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper packet-bounds flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let bytes = "x"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_store_bytes' requires arg4 flags"
    }
    {
        name: "tc-subfn-skb-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def mutate [skb bytes] {'
            '    helper-call "bpf_skb_store_bytes" $skb 0 $bytes 1 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  mutate $ctx $bytes'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-subfn-skb-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def mutate [skb bytes] {'
            '    helper-call "bpf_skb_store_bytes" $skb 0 $bytes 1 0'
            '    0'
            '  }'
            '  let bytes = "x"'
            '  mutate $ctx $bytes'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-subfn-skb-pull-data-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  pull $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-subfn-skb-pull-data-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  pull $ctx'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-nested-subfn-skb-pull-data-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function nested packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def mutate [skb] {'
            '    let actual = (id $skb)'
            '    helper-call "bpf_skb_pull_data" $actual 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  mutate $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-record-context-helper-arg"
        category: "helper-state"
        tags: [tc helper record context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { skb: $ctx }'
            '  helper-call "bpf_skb_pull_data" $rec.skb 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-context-helper-arg"
        category: "helper-state"
        tags: [tc helper user-function record context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [x] { { skb: $x } }'
            '  let rec = (wrap $ctx)'
            '  helper-call "bpf_skb_pull_data" $rec.skb 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-raw-context-helper-arg"
        category: "helper-state"
        tags: [tc helper user-function context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  pull $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l3-csum-replace-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-l3-csum-replace-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l3-csum-replace-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper checksum flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_l3_csum_replace' requires arg4 flags"
    }
    {
        name: "tc-l4-csum-replace-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-l4-csum-replace-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l4-csum-replace-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper checksum flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_l4_csum_replace' requires arg4 flags"
    }
    {
        name: "tc-csum-update-preserves-packet-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_csum_update" $ctx 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-set-hash-invalid-preserves-packet-data"
        category: "helper-state"
        tags: [tc helper hash packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_set_hash_invalid" $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-set-hash-invalid-rejects-return-use"
        category: "helper-state"
        tags: [tc helper hash void-return reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_hash_invalid" $ctx | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void helper 'bpf_set_hash_invalid' return value cannot be used"
    }
    {
        name: "tc-skb-pull-data-rejects-socket-ctx-arg"
        category: "helper-state"
        tags: [tc helper raw-context reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk { helper-call "bpf_skb_pull_data" $sk 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_pull_data' arg0 expects raw context pointer"
    }
    {
        name: "tc-fib-lookup-rejects-socket-ctx-arg"
        category: "helper-state"
        tags: [tc helper fib raw-context reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:4 --max-entries 1'
            '  let params = (0 | map-get scratch --kind array)'
            '  let sk = $ctx.sk'
            '  if $sk { if $params { helper-call "bpf_fib_lookup" $sk $params 4 0 } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' arg0 expects raw context pointer"
    }
    {
        name: "tc-fib-lookup-helper"
        category: "helper-state"
        tags: [tc helper fib accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-fib-lookup-rejects-small-params-buffer"
        category: "helper-state"
        tags: [tc helper fib bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:8 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper fib_lookup params requires 64 bytes"
    }
    {
        name: "xdp-fib-lookup-helper"
        category: "helper-state"
        tags: [xdp helper fib accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-fib-lookup-rejects-invalid-flags"
        category: "helper-state"
        tags: [xdp helper fib flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 64 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' requires arg3 flags"
    }
    {
        name: "xdp-fib-lookup-rejects-dynamic-flags"
        category: "helper-state"
        tags: [xdp helper fib flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 $flags }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' requires arg3 flags"
    }
    {
        name: "xdp-fib-lookup-rejects-small-params-buffer"
        category: "helper-state"
        tags: [xdp helper fib bounds reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:8 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper fib_lookup params requires 64 bytes"
    }
    {
        name: "sk-skb-fib-lookup-rejects-program"
        category: "helper-state"
        tags: [sk-skb helper fib program-policy reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "xdp-check-mtu-helper"
        category: "helper-state"
        tags: [xdp helper mtu accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-check-mtu-rejects-nonzero-flags"
        category: "helper-state"
        tags: [xdp helper mtu flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 1 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
    }
    {
        name: "xdp-check-mtu-rejects-dynamic-flags"
        category: "helper-state"
        tags: [xdp helper mtu flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 $flags }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
    }
    {
        name: "tc-check-mtu-helper"
        category: "helper-state"
        tags: [tc helper mtu accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 1 }'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-check-mtu-rejects-small-mtu-len"
        category: "helper-state"
        tags: [tc helper mtu bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:2 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper check_mtu mtu_len requires 4 bytes"
    }
    {
        name: "sk-skb-check-mtu-rejects-program"
        category: "helper-state"
        tags: [sk-skb helper mtu program-policy reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "tc-skb-get-tunnel-key-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-get-tunnel-key-rejects-invalid-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 2 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-get-tunnel-key-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-get-tunnel-opt-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_get_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tunnel-key-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
