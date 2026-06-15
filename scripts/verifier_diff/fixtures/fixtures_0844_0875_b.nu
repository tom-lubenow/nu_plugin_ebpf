const VERIFIER_DIFF_FIXTURES_0844_0875_B = [
    {
        name: "flow-dissector-flow-key-alias-context"
        category: "context-surface"
        tags: [flow-dissector context alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let keys = $ctx.flow_keys'
            '  ($keys.protocol + $keys.transport_header_offset + $keys.src_port + $keys.destination_ip4 + ($keys.dst_ip6 | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  $ctx.flow_keys.nhoff = 14'
            '  $ctx.flow_keys.ipv6_dst.3 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-alias-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.protocol = 6'
            '  $keys.network_header_offset = 14'
            '  $keys.dst_ip6.3 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-returned-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event.flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-returned-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function alias get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
