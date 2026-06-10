const VERIFIER_DIFF_FIXTURES_0907_0937 = [
    {
        name: "cgroup-sockopt-optval-record-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-record-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-record-direct-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] {'
            '    let base = { optval: $optval }'
            '    { ok: true, ...$base }'
            '  }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-nested-user-function-record-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record spread nested source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  def outer [event] {'
            '    let optval = $event.optval'
            '    let base = (wrap $optval)'
            '    { ok: true, ...$base }'
            '  }'
            '  mut rec = (outer $ctx)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-setsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_setsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-rejects-non-socket-option-context"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_getsockopt' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs"
    }
    {
        name: "source-helper-get-retval-cgroup-device"
        category: "helper-state"
        tags: [helper-call cgroup-retval source accept]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-set-retval-cgroup-sock"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sockopt source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-set-retval-cgroup-sock-addr-sendmsg"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock-addr source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-cgroup-sysctl"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sysctl source accept]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-rejects-non-cgroup-context"
        category: "helper-state"
        tags: [helper-call cgroup-retval source reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs"
    }
    {
        name: "source-helper-set-retval-rejects-cgroup-sock-addr-getpeername"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock-addr source reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_set_retval' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks"
    }
    {
        name: "cgroup-sockopt-get-context-fields"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  ($ctx.level + $ctx.optname + $ctx.optlen + $ctx.retval + $ctx.netns_cookie) | count'
            '  if $ctx.optval { 1 | count }'
            '  if $ctx.optval_end { 1 | count }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-optlen-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-rejects-level-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.level is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-get-rejects-optname-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optname = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optname is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-without-index"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-read"
        category: "context-policy"
        tags: [cgroup-sockopt reject context]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.0 = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optval is only available on cgroup_sockopt programs"
    }
    {
        name: "cgroup-sockopt-bound-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-bound-parenthesized-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sockopt context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp {'
            '    $tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-bound-tcp-helper-pointer"
        category: "context-surface"
        tags: [cgroup-sockopt context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp {'
            '    $tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-record-bound-tcp-helper-pointer"
        category: "context-surface"
        tags: [cgroup-sockopt context record alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp {'
            '    $rec.tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-full-helper-pointer"
        category: "context-surface"
        tags: [tc context alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-context-root-projection"
        category: "context-surface"
        tags: [tc context user-function alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [event] { $event.sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-context-root-projection"
        category: "context-surface"
        tags: [tc context record source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-bound-context-root-projection"
        category: "context-surface"
        tags: [tc context record alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { socket: $sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
