[
    {
        target: "tracepoint:syscalls/sys_enter_seccomp"
        program: [
            '{|ctx|'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.op + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_seccomp:field:uargs"
            "tracepoint:syscalls/sys_enter_seccomp:field:op"
            "tracepoint:syscalls/sys_enter_seccomp:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_clone"
        program: [
            '{|ctx|'
            '  let parent_tidptr = $ctx.parent_tidptr'
            '  let child_tidptr = $ctx.child_tidptr'
            '  if $parent_tidptr { 1 | count }'
            '  if $child_tidptr { 1 | count }'
            '  ($ctx.clone_flags + $ctx.newsp + $ctx.tls) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_clone:field:parent_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:child_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:clone_flags"
            "tracepoint:syscalls/sys_enter_clone:field:newsp"
            "tracepoint:syscalls/sys_enter_clone:field:tls"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_syslog"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.type + $ctx.len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_syslog:field:buf"
            "tracepoint:syscalls/sys_enter_syslog:field:type"
            "tracepoint:syscalls/sys_enter_syslog:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_personality"
        program: [
            '{|ctx|'
            '  $ctx.personality | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_personality:field:personality"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 0)) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:id"
            "tracepoint:syscalls/sys_enter_openat:field:args"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_exit_openat2"
        program: [
            '{|ctx|'
            '  ($ctx.id + $ctx.ret) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_exit_openat2:field:id"
            "tracepoint:syscalls/sys_exit_openat2:field:ret"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.ifindex | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys.ip_proto | count'
            '  "fallback"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
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
