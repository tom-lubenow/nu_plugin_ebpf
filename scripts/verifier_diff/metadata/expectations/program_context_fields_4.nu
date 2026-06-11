const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS_4 = [
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
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  $file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0.orig_ax | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
    }
    {
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let regs = $ctx.arg0'
            '  $regs.orig_ax | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
    }
    {
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:cpu" "ctx:timestamp" "ctx:cgroup_id" "helper:bpf_get_smp_processor_id" "helper:bpf_ktime_get_ns" "helper:bpf_get_current_cgroup_id"]
    }
    {
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:cpu" "ctx:timestamp" "ctx:cgroup_id" "helper:bpf_get_smp_processor_id" "helper:bpf_ktime_get_ns" "helper:bpf_get_current_cgroup_id"]
    }
    {
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:access_type" "ctx:device_access" "ctx:device_type" "ctx:major" "ctx:minor"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.sock_type + $ctx.protocol + $ctx.state + $ctx.rx_queue_mapping + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:bound_dev_if"
            "ctx:family"
            "ctx:mark"
            "ctx:netns_cookie"
            "ctx:priority"
            "ctx:protocol"
            "ctx:rx_queue_mapping"
            "ctx:sk"
            "ctx:sock_type"
            "ctx:socket_cookie"
            "ctx:state"
            "helper:bpf_get_netns_cookie"
            "helper:bpf_get_socket_cookie"
            "helper:bpf_probe_read_kernel"
        ]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6" "ctx:local_port" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_port" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:remote_ip4" "ctx:remote_port" "ctx:sk" "ctx:user_ip4" "ctx:user_port" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  ($ctx.level + $ctx.optname + $ctx.optlen + $ctx.retval + $ctx.netns_cookie) | count'
            '  if $ctx.optval { 1 | count }'
            '  if $ctx.optval_end { 1 | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:level"
            "ctx:netns_cookie"
            "ctx:optlen"
            "ctx:optname"
            "ctx:optval"
            "ctx:optval_end"
            "ctx:sockopt_retval"
            "helper:bpf_get_netns_cookie"
        ]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = 0'
            '  $ctx.new_value = "1"'
            '  $ctx.name | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:file_pos" "ctx:sysctl_name" "ctx:sysctl_new_value" "helper:bpf_sysctl_get_name"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.write + $ctx.file_pos) | count'
            '  $ctx.base_name | count'
            '  $ctx.current_value | count'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:file_pos"
            "ctx:sysctl_base_name"
            "ctx:sysctl_current_value"
            "ctx:sysctl_new_value"
            "ctx:write"
            "helper:bpf_sysctl_get_current_value"
            "helper:bpf_sysctl_get_name"
            "helper:bpf_sysctl_get_new_value"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.reply + ($ctx.replylong | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.reply = 1'
            '  $ctx.replylong.0 = 7'
            '  $ctx.cb_flags = 1'
            '  $ctx.sk_txhash = 7'
            '  1'
            '}'
        ]
        feature_keys: [
            "ctx:args"
            "ctx:cb_flags"
            "ctx:family"
            "ctx:netns_cookie"
            "ctx:op"
            "ctx:remote_port"
            "ctx:reply"
            "ctx:replylong"
            "ctx:sk"
            "ctx:sk_txhash"
            "ctx:socket_cookie"
            "helper:bpf_get_netns_cookie"
            "helper:bpf_get_socket_cookie"
            "helper:bpf_probe_read_kernel"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.is_fullsock + $ctx.snd_cwnd + $ctx.srtt_us + $ctx.state + $ctx.rtt_min + $ctx.snd_ssthresh + $ctx.rcv_nxt + $ctx.snd_nxt) | count'
            '  ($ctx.snd_una + $ctx.mss_cache + $ctx.ecn_flags + $ctx.rate_delivered + $ctx.rate_interval_us + $ctx.packets_out + $ctx.retrans_out + $ctx.total_retrans) | count'
            '  ($ctx.segs_in + $ctx.data_segs_in + $ctx.segs_out + $ctx.data_segs_out + $ctx.lost_out + $ctx.sacked_out + ($ctx.bytes_received mod 1024) + ($ctx.bytes_acked mod 1024)) | count'
            '  1'
            '}'
        ]
        feature_keys: [
            "ctx:bytes_acked"
            "ctx:bytes_received"
            "ctx:data_segs_in"
            "ctx:data_segs_out"
            "ctx:ecn_flags"
            "ctx:is_fullsock"
            "ctx:lost_out"
            "ctx:mss_cache"
            "ctx:packets_out"
            "ctx:rate_delivered"
            "ctx:rate_interval_us"
            "ctx:rcv_nxt"
            "ctx:retrans_out"
            "ctx:rtt_min"
            "ctx:sacked_out"
            "ctx:segs_in"
            "ctx:segs_out"
            "ctx:snd_cwnd"
            "ctx:snd_nxt"
            "ctx:snd_ssthresh"
            "ctx:snd_una"
            "ctx:srtt_us"
            "ctx:state"
            "ctx:total_retrans"
        ]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.protocol + $ctx.ip_protocol + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.cookie + $ctx.ingress_ifindex) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 3)) | count'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "ctx:cookie"
            "ctx:family"
            "ctx:ingress_ifindex"
            "ctx:local_ip4"
            "ctx:local_ip6"
            "ctx:local_port"
            "ctx:protocol"
            "ctx:remote_ip4"
            "ctx:remote_ip6"
            "ctx:remote_port"
        ]
    }
    {
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  $ctx.arg.address.sa_family | count'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sysctl_new_value" "helper:bpf_sysctl_get_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sysctl_new_value"]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data" "ctx:packet_len" "ctx:eth_protocol" "ctx:protocol" "ctx:hash" "ctx:bind_inany" "ctx:socket_cookie" "ctx:sk" "ctx:family" "ctx:mark" "ctx:priority" "ctx:rx_queue_mapping" "helper:bpf_get_socket_cookie" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = ($ctx | get data)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event | get data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { data: ($ctx | get data) })'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get data) data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: null } | update data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: ($ctx | get data), keep: 1 } | select data keep | reject keep | rename packet)'
            '  $rec.packet.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: ($ctx | get data) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  mut rec = { data: (id ($ctx | get data)) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
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
        feature_keys: ["ctx:data"]
    }
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
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
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
            '  mut ctx = $ctx'
            '  $ctx.mark = (if $ctx.pid == 0 { 7 } else { 1 })'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|event|'
            '  mut event = $event'
            '  $event.mark = 7'
            '  $event.priority = 3'
            '  $event.cb.1 = 9'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:priority" "ctx:cb"]
    }
    {
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_meta" "ctx:iter_task" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_file" "helper:bpf_probe_read_kernel"]
    }
]
