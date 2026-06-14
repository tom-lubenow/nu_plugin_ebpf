[
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: null } | update keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: ($ctx | get flow_keys), keep: 1 } | select keys keep | reject keep | rename parsed)'
            '  $rec.parsed.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let base = { keys: $ctx.flow_keys }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def wrap [keys] { { keys: $keys } }'
            '  let keys = $ctx.flow_keys'
            '  mut rec = (wrap $keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.state.in.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let state = ($ctx.nf_state)'
            '  let skb = $ctx.skb'
            '  ($state.in.ifindex + $skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let input = $ctx.state.in'
            '  $input.ifindex | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state"]
    }
]
