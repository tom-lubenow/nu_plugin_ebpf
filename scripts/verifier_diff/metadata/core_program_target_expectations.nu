const PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "fentry:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline"] }
    { target: "fentry.s:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "fexit:ksys_read" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline"] }
    { target: "fexit.s:ksys_read" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "fmod_ret:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline"] }
    { target: "fmod_ret.s:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "tp_btf:sys_enter" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING"] }
    { target: "lsm:file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM"] }
    { target: "lsm_cgroup:socket_bind" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM" "attach:BPF_LSM_CGROUP"] }
    { target: "lsm.s:file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM" "section:sleepable-program"] }
    { target: "struct_ops:sched_ext_ops.init" feature_keys: ["kernel:btf-vmlinux" "program:bpf-trampoline" "program:BPF_PROG_TYPE_STRUCT_OPS" "struct_ops:sched_ext_ops" "section:sleepable-program"] }
    { target: "struct_ops:tcp_congestion_ops" feature_keys: ["kernel:btf-vmlinux" "program:bpf-trampoline" "program:BPF_PROG_TYPE_STRUCT_OPS" "struct_ops:tcp_congestion_ops"] }
    { target: "kprobe.multi:vfs_*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_KPROBE_MULTI"] }
    { target: "kretprobe.multi:vfs_*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_KPROBE_MULTI"] }
    { target: "uprobe.s:/bin/bash:main" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "section:sleepable-program"] }
    { target: "uretprobe.s:/lib/libc.so.6:malloc" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "section:sleepable-program"] }
    { target: "uprobe.multi:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI"] }
    { target: "uretprobe.multi:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI"] }
    { target: "uprobe.multi.s:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI" "section:sleepable-program"] }
    { target: "uretprobe.multi.s:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI" "section:sleepable-program"] }
    { target: "raw_tracepoint.w:sys_enter" feature_keys: ["program:BPF_PROG_TYPE_RAW_TRACEPOINT" "section:raw_tracepoint.w"] }
    { target: "tracepoint:syscalls/sys_enter_openat" feature_keys: ["program:BPF_PROG_TYPE_TRACEPOINT"] }
    { target: "perf_event:software:cpu-clock:period=100000" feature_keys: ["program:BPF_PROG_TYPE_PERF_EVENT"] }
    { target: "xdp:lo" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-skb"] }
    { target: "xdp:lo:drv:frags" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-drv" "section:xdp.frags"] }
    { target: "xdp:lo:hw" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-hw"] }
    { target: "xdp:devmap" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:BPF_XDP_DEVMAP"] }
    { target: "xdp:cpumap" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:BPF_XDP_CPUMAP"] }
    { target: "socket_filter:tcp4:127.0.0.1:8080" feature_keys: ["program:BPF_PROG_TYPE_SOCKET_FILTER"] }
    { target: "tc:lo:ingress" feature_keys: ["program:BPF_PROG_TYPE_SCHED_CLS"] }
    { target: "tc_action:demo-action" feature_keys: ["program:BPF_PROG_TYPE_SCHED_ACT"] }
    { target: "tcx:lo:egress" feature_keys: ["attach:tcx"] }
    { target: "netkit:lo:peer" feature_keys: ["attach:netkit"] }
    { target: "flow_dissector:/proc/self/ns/net" feature_keys: ["program:BPF_PROG_TYPE_FLOW_DISSECTOR"] }
    { target: "netfilter:ipv4:pre_routing" feature_keys: ["attach:netfilter-link"] }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" feature_keys: ["attach:netfilter-link" "attach:netfilter-defrag"] }
    { target: "lwt_seg6local:demo-route" feature_keys: ["program:BPF_PROG_TYPE_LWT" "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"] }
    { target: "sk_lookup:/proc/self/ns/net" feature_keys: ["program:BPF_PROG_TYPE_SK_LOOKUP"] }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_MSG"] }
    { target: "sk_skb:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_SKB"] }
    { target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_SKB"] }
    { target: "sk_reuseport:select" feature_keys: ["attach:BPF_SK_REUSEPORT_SELECT"] }
    { target: "sk_reuseport:migrate" feature_keys: ["attach:BPF_SK_REUSEPORT_SELECT" "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"] }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SKB"] }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"] }
    { target: "cgroup_sock_addr:/sys/fs/cgroup_unix:connect4" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"] }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR" "attach:BPF_CGROUP_UNIX_SOCK_ADDR"] }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCKOPT"] }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK"] }
    { target: "cgroup_device:/sys/fs/cgroup" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_DEVICE"] }
    { target: "cgroup_sysctl:/sys/fs/cgroup" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SYSCTL"] }
    { target: "sock_ops:/sys/fs/cgroup" feature_keys: ["program:BPF_PROG_TYPE_SOCK_OPS"] }
    { target: "lirc_mode2:/dev/lirc0" feature_keys: ["program:BPF_PROG_TYPE_LIRC_MODE2"] }
    { target: "iter:task_vma" feature_keys: ["program:BPF_PROG_TYPE_TRACING-iter" "iter-target:task_vma"] }
    { target: "syscall:demo" feature_keys: ["program:BPF_PROG_TYPE_SYSCALL"] }
    { target: "freplace:replace_me" feature_keys: ["program:BPF_PROG_TYPE_EXT"] }
]
