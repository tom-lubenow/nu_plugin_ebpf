const PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let text = "kfunc-call \"bpf_task_from_pid\" 1"'
            '  # kfunc-call "bpf_task_from_pid" 1'
            '  let ignored = 0 # | kfunc-call "bpf_task_from_pid" 1'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_rcu_read_lock" "kfunc:bpf_rcu_read_unlock"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_preempt_disable" "kfunc:bpf_preempt_enable"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_local_irq_save" "kfunc:bpf_local_irq_restore"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        feature_keys: [
            "kfunc:bpf_res_spin_lock"
            "kfunc:bpf_res_spin_unlock"
            "kfunc:bpf_res_spin_lock_irqsave"
            "kfunc:bpf_res_spin_unlock_irqrestore"
        ]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup_unix:connect4"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  let text = "$event.sun_path = /tmp/nu-ebpf.sock"'
            '  # $event.sun_path = /tmp/nu-ebpf.sock'
            '  if $event.sun_path == "/tmp/nu-ebpf.sock" { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
]

const PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.4"
            source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c"
        }
    }
    {
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.arg0 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }
]
