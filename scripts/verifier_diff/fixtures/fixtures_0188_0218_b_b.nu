const VERIFIER_DIFF_FIXTURES_0188_0218_B_B = [
    {
        name: "xdp-packet-count"
        category: "packet"
        tags: [xdp counter]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-derived-header-fields"
        category: "packet"
        tags: [xdp packet header bitfield source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let ip4 = ($ctx.data.eth.ipv4.version + $ctx.data.eth.ipv4.ihl + $ctx.data.eth.ipv4.dscp + $ctx.data.eth.ipv4.ecn + $ctx.data.eth.ipv4.flags + $ctx.data.eth.ipv4.dont_fragment + $ctx.data.eth.ipv4.more_fragments + $ctx.data.eth.ipv4.fragment_offset)'
            '  let ip6 = ($ctx.data.eth.ipv6.version + $ctx.data.eth.ipv6.traffic_class + $ctx.data.eth.ipv6.flow_label)'
            '  let tcp = ($ctx.data.eth.ipv4.tcp.data_offset + $ctx.data.eth.ipv4.tcp.flags + $ctx.data.eth.ipv4.tcp.syn)'
            '  ($ip4 + $ip6 + $tcp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-bitfield-writes"
        category: "packet"
        tags: [xdp packet header bitfield write source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.ipv4.version = 4'
            '  $ctx.data.eth.ipv4.flags = 2'
            '  $ctx.data.eth.ipv4.tcp.syn = 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-arp-header-fields"
        category: "packet"
        tags: [xdp packet header arp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let arp = ($ctx.data.eth.arp.hardware_type + $ctx.data.eth.arp.protocol_type + $ctx.data.eth.arp.hardware_len + $ctx.data.eth.arp.protocol_len + $ctx.data.eth.arp.opcode)'
            '  $arp | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-header-field-aliases"
        category: "packet"
        tags: [xdp packet header alias source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let eth = $ctx.data.eth.h_proto'
            '  let ip4 = ($ctx.data.eth.ipv4.tot_len + $ctx.data.eth.ipv4.saddr.0 + $ctx.data.eth.ipv4.daddr.0)'
            '  let udp = ($ctx.data.eth.ipv4.udp.source + $ctx.data.eth.ipv4.udp.dest)'
            '  ($eth + $ip4 + $udp) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-icmp-echo-fields"
        category: "packet"
        tags: [xdp packet header icmp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let icmp4 = ($ctx.data.eth.ipv4.icmp.rest_of_header + $ctx.data.eth.ipv4.icmp.echo_id + $ctx.data.eth.ipv4.icmp.echo_sequence)'
            '  let icmp6 = ($ctx.data.eth.ipv6.icmpv6.rest + $ctx.data.eth.ipv6.icmpv6.identifier + $ctx.data.eth.ipv6.icmpv6.sequence)'
            '  ($icmp4 + $icmp6) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-esp-header-fields"
        category: "packet"
        tags: [xdp packet header esp source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let esp4 = ($ctx.data.eth.ipv4.esp.spi + $ctx.data.eth.ipv4.esp.sequence)'
            '  let esp6 = ($ctx.data.eth.ipv6.esp.security_parameter_index + $ctx.data.eth.ipv6.esp.seq)'
            '  ($esp4 + $esp6) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
