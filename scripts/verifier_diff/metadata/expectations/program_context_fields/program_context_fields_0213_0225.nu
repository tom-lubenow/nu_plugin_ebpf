[
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: $ctx.data_meta }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: ($ctx | get data_meta) }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert meta ($ctx | get data_meta))'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut meta = ($ctx | get data_meta)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event | get data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let base = { meta: $ctx.data_meta }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
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
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.2) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pkt_type" "ctx:queue_mapping" "ctx:vlan_present" "ctx:vlan_tci" "ctx:vlan_proto" "ctx:hash_recalc" "ctx:csum_level" "ctx:socket_cookie" "ctx:socket_uid" "ctx:sk" "ctx:family" "ctx:cb" "helper:bpf_get_hash_recalc" "helper:bpf_csum_level" "helper:bpf_get_socket_cookie" "helper:bpf_get_socket_uid" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm + $ctx.cb.3) | count'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:pkt_type" "ctx:queue_mapping" "ctx:vlan_present" "ctx:vlan_tci" "ctx:vlan_proto" "ctx:hash_recalc" "ctx:csum_level" "ctx:cgroup_classid" "ctx:route_realm" "ctx:cb" "helper:bpf_get_hash_recalc" "helper:bpf_csum_level" "helper:bpf_get_cgroup_classid" "helper:bpf_get_route_realm"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.queue_mapping = 1'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:queue_mapping" "ctx:cb" "ctx:tc_classid" "ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
]
