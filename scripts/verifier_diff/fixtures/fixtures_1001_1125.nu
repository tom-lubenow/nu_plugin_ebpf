const VERIFIER_DIFF_FIXTURES_1001_1125 = [
    {
        name: "sk-reuseport-rejects-migrating-sk-on-packet-context"
        category: "context-policy"
        tags: [sk-reuseport reject context]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.migrating_sk | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.migrating_sk is only available on sk_reuseport programs"
    }
    {
        name: "sk-reuseport-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-reuseport reject context writable]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-reuseport-rejects-skb-pkt-type-context"
        category: "context-policy"
        tags: [sk-reuseport reject context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  $ctx.pkt_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pkt_type is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-reuseport-rejects-skb-vlan-context"
        category: "context-policy"
        tags: [sk-reuseport reject context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  $ctx.vlan_tci | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.vlan_tci is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-lookup-context-clear-socket"
        category: "context-surface"
        tags: [sk-lookup context writable]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.ip_protocol + $ctx.local_port + $ctx.remote_port + $ctx.cookie + $ctx.ingress_ifindex + $ctx.sk.family) | count'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-context-clear-socket-aliases"
        category: "context-surface"
        tags: [sk-lookup context writable socket alias]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sock = 0'
            '  $ctx.socket = 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-tuple-cookie-context"
        category: "context-surface"
        tags: [sk-lookup context source metadata]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.protocol + $ctx.ip_protocol + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.cookie + $ctx.ingress_ifindex) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 3)) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-lookup context socket source metadata]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.family + $sk.local_port + $sk.remote_port + $sk.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-lookup context socket alias source metadata]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let sock = $ctx.sock'
            '  ($sock.family + $ctx.socket.dst_port + $sock.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-lookup-rejects-socket-cookie-context"
        category: "context-policy"
        tags: [sk-lookup reject context socket]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.socket_cookie | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.socket_cookie is only available"
    }
    {
        name: "sk-lookup-rejects-socket-uid-context"
        category: "context-policy"
        tags: [sk-lookup reject context socket]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.socket_uid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.socket_uid is only available"
    }
    {
        name: "sk-lookup-rejects-packet-data-context"
        category: "context-policy"
        tags: [sk-lookup reject context packet]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data"
    }
    {
        name: "sk-lookup-rejects-sk-indexed-assignment"
        category: "context-policy"
        tags: [sk-lookup reject context writable]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk.0 = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk does not support indexed assignment"
    }
    {
        name: "sk-msg-basic-context"
        category: "context-surface"
        tags: [sk-msg context]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.family + $ctx.local_port + $ctx.remote_port + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-rich-context"
        category: "context-surface"
        tags: [sk-msg context packet socket source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.len + $ctx.size + $ctx.remote_ip4 + $ctx.local_ip4 + ($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 1)) | count'
            '  if $ctx.data_end { 1 | count }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-msg context socket source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.src_port + $sk.dst_port + $sk.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-msg context socket alias source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.sock.src_port + $ctx.socket.dst_port + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-data-context-write"
        category: "context-surface"
        tags: [sk-msg context packet writable]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.data | get 0) | count'
            '  $ctx.data.0 = 42'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-msg-rejects-fullsock-projection"
        category: "context-policy"
        tags: [sk-msg reject socket helper-backed]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.sk.full.family | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_fullsock' is only valid"
    }
    {
        name: "sk-msg-rejects-socket-uid-context"
        category: "context-policy"
        tags: [sk-msg reject context socket]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.socket_uid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.socket_uid is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "sk-msg-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-msg reject context writable]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-msg-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-msg reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket --kind reuseport-sockarray is only valid in sk_reuseport programs"
    }
    {
        name: "sk-skb-basic-context"
        category: "context-surface"
        tags: [sk-skb context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.eth_protocol + $ctx.local_port + $ctx.socket_uid + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-rich-context"
        category: "context-surface"
        tags: [sk-skb context packet helper-backed source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.family + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.1) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-skb context socket source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.local_port + $sk.remote_port + $sk.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-skb context socket alias source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-data-context-write"
        category: "context-surface"
        tags: [sk-skb context packet writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.protocol + $ctx.priority) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-metadata-context-write"
        category: "context-surface"
        tags: [sk-skb context writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 5'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-rejects-mark-context"
        category: "context-policy"
        tags: [sk-skb reject context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.mark | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-rejects-tstamp-context"
        category: "context-policy"
        tags: [sk-skb reject context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-skb reject context writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-skb-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-skb reject]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket --kind reuseport-sockarray is only valid in sk_reuseport programs"
    }
    {
        name: "sk-skb-parser-basic-context"
        category: "context-surface"
        tags: [sk-skb-parser context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.eth_protocol + $ctx.local_port + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-rich-context"
        category: "context-surface"
        tags: [sk-skb-parser context packet helper-backed source metadata]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.family + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.2) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-data-context-write"
        category: "context-surface"
        tags: [sk-skb-parser context packet writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.protocol + $ctx.priority) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.priority = 3'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-bound-socket-projection-context"
        category: "context-surface"
        tags: [sk-skb-parser context socket source metadata]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  ($sk.local_port + $sk.remote_port + $sk.priority) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-skb-parser context socket alias source metadata]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port + $ctx.socket.priority) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-metadata-context-write"
        category: "context-surface"
        tags: [sk-skb-parser context writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 5'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-skb-parser-rejects-mark-context"
        category: "context-policy"
        tags: [sk-skb-parser reject context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.mark | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-parser-rejects-tstamp-context"
        category: "context-policy"
        tags: [sk-skb-parser reject context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "sk-skb-parser-rejects-sk-assignment"
        category: "context-policy"
        tags: [sk-skb-parser reject context writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is read-only"
    }
    {
        name: "sk-skb-parser-rejects-reuseport-redirect"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser reject]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket --kind reuseport-sockarray is only valid in sk_reuseport programs"
    }
    {
        name: "lwt-xmit-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.priority + $ctx.cb.3) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.mark) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.cb.1 = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-record-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable record source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-record-spread-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable record spread source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-user-function-record-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable user-function record source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  mut rec = (wrap $ctx.data)'
            '  $rec.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-metadata-context-write"
        category: "context-surface"
        tags: [lwt context writable source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.2 = 9'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-rejects-packet-data-write"
        category: "context-policy"
        tags: [lwt reject context packet writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.0 = 42'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on lwt_in programs"
    }
    {
        name: "lwt-in-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.mark) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.0) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.queue_mapping + $ctx.protocol + $ctx.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.2) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-rejects-csum-level-context"
        category: "context-policy"
        tags: [lwt reject context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.csum_level | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.csum_level is only available on lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "lwt-seg6local-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.hash + $ctx.route_realm + $ctx.gso_size) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-rich-skb-context"
        category: "context-surface"
        tags: [lwt context packet helper-backed source metadata seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.mark + $ctx.priority + $ctx.cb.4) | count'
            '  ($ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-context-write"
        category: "context-surface"
        tags: [lwt context writable seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.4 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-rejects-tstamp-context"
        category: "context-policy"
        tags: [lwt reject context timestamp]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tstamp | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    }
    {
        name: "lwt-xmit-rejects-sk-assignment"
        category: "context-policy"
        tags: [lwt reject context writable socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available"
    }
    {
        name: "lwt-xmit-rejects-tc-classid-context"
        category: "context-policy"
        tags: [lwt reject context]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tc_classid | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "lwt-xmit-rejects-socket-context"
        category: "context-policy"
        tags: [lwt reject context socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    }
    {
        name: "lwt-push-encap-rejects-non-lwt-program"
        category: "helper-policy"
        tags: [lwt helper-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs"
    }
    {
        name: "lwt-xmit-push-encap-helper"
        category: "helper-state"
        tags: [lwt helper-call accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  map-define encap_hdr --kind array --value-type bytes:16 --max-entries 1'
            '  let hdr = (0 | map-get encap_hdr --kind array)'
            '  if $hdr { helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16 }'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-push-encap-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds reject source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16'
            '  ($data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-xmit-push-encap-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16'
            '  ($ctx.data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:16 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-seg6local-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-adjust-srh-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_seg6_adjust_srh" $ctx 0 4'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-action-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_action --kind array --value-type bytes:16 --max-entries 1'
            '  let param = (0 | map-get seg6_action --kind array)'
            '  if $param { helper-call "bpf_lwt_seg6_action" $ctx 0 $param 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds dynamic reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes_dyn_short --kind array)'
            '  if $bytes {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes $size'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lirc-mode2-context"
        category: "context-surface"
        tags: [lirc context]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.sample + $ctx.value + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-current-context"
        category: "context-surface"
        tags: [lirc context current]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-rc-helpers"
        category: "helper-state"
        tags: [lirc helper-call accept source metadata]
        target: "lirc_mode2:/dev/null"
        program: [
            '{|ctx|'
            '  helper-call "bpf_rc_repeat" $ctx'
            '  helper-call "bpf_rc_keydown" $ctx 0 0 0'
            '  helper-call "bpf_rc_pointer_rel" $ctx 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tracepoint-writable-args"
        category: "context-surface"
        tags: [raw-tracepoint-w context]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-writable-current-context"
        category: "context-surface"
        tags: [raw-tracepoint-w context current]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.meta { 1 | count }'
            '  if $ctx.task { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.task { $ctx.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-meta-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  $ctx.meta.seq_num | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-alias-btf-fields"
        category: "context-surface"
        tags: [iter context alias btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-record-btf-fields"
        category: "context-surface"
        tags: [iter context record btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let rec = { meta: $ctx.iter_meta task: $ctx.iter_task }'
            '  $rec.meta.seq_num | count'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-record-spread-btf-fields"
        category: "context-surface"
        tags: [iter context record spread btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let base = { task: $ctx.iter_task }'
            '  let rec = { meta: $ctx.iter_meta, ...$base }'
            '  $rec.meta.seq_num | count'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-user-function-record-btf-fields"
        category: "context-surface"
        tags: [iter context user-function record btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  def wrap [task] { { task: $task } }'
            '  let rec = (wrap $ctx.iter_task)'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-user-function-returned-btf-root-fields"
        category: "context-surface"
        tags: [iter context user-function alias btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event.iter_meta }'
            '  def get_task [event] { $event.iter_task }'
            '  let meta = (get_meta $ctx)'
            '  let task = (get_task $ctx)'
            '  $meta.seq_num | count'
            '  if $task { $task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-file-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.file { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-file-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-vma-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.vma { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-vma-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.vma { $ctx.vma.vm_start | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-cgroup-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-cgroup-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { $ctx.cgroup.level | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-btf-field"
        category: "context-surface"
        tags: [iter context map btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-elem-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-elem-map-btf-field"
        category: "context-surface"
        tags: [iter context map btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-sk-storage-map-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-sk-storage-map-btf-fields"
        category: "context-surface"
        tags: [iter context map socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  if $ctx.sk { $ctx.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-sockmap-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-sockmap-btf-fields"
        category: "context-surface"
        tags: [iter context map socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  if $ctx.sk { $ctx.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { $ctx.prog.len | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { $ctx.link.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.sk_common { 1 | count }'
            '  if $ctx.sock_common { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  if $ctx.sk_common { $ctx.sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-udp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  ($ctx.uid + $ctx.bucket) | count'
            '  if $ctx.udp_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-udp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  if $ctx.udp_sk { $ctx.udp_sk.inet.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-unix-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.unix_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-unix-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  if $ctx.unix_sk { $ctx.unix_sk.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-dmabuf-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-dmabuf-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { $ctx.dmabuf.size | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ipv6-route-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { 1 | count }'
            '  if $ctx.ipv6_route { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ipv6-route-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { $ctx.rt.fib6_metric | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-kmem-cache-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-kmem-cache-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { $ctx.kmem_cache.size | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ksym-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ksym-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { $ctx.ksym.value | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-netlink-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-netlink-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { $ctx.netlink_sk.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-rejects-queue"
        category: "maps"
        tags: [queue reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-get q --kind queue'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get is not supported for map kind queue"
    }
    {
        name: "map-define-kptr-slot"
        category: "maps"
        tags: [maps map-define kptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-kptr-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define kptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind queue --value-type "record{task:kptr:task_struct,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kptr fields, which are currently supported for hash, array, and lru-hash maps"
    }
]
