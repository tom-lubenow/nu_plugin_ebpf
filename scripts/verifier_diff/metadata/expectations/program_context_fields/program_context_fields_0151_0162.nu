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
]
