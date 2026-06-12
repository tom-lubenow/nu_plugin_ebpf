def struct-ops-target-sleepable? [target: string] {
    if not ($target | str starts-with "struct_ops:sched_ext_ops.") {
        return false
    }

    let callback = (
        $target
        | split row "struct_ops:sched_ext_ops."
        | get 1
        | split row ":"
        | first
    )

    $callback in $SCHED_EXT_SLEEPABLE_CALLBACKS
}

def program-struct-ops-kernel-features [source: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "struct_ops:sched_ext_ops") {
        return []
    }

    mut features = []
    if (struct-ops-target-sleepable? $target_text) {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
    }

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        for callback in $SCHED_EXT_SLEEPABLE_CALLBACKS {
            if ($trimmed | str starts-with $"($callback):") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
            }
        }
    }

    $features
}
def target-kernel-features [target] {
    if $target == null {
        return []
    }

    mut features = []

    if ($target | str starts-with "fentry.s:") or ($target | str starts-with "fexit.s:") or ($target | str starts-with "fmod_ret.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "fentry:") or ($target | str starts-with "fexit:") or ($target | str starts-with "fmod_ret:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
    } else if ($target | str starts-with "tp_btf:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
    } else if ($target | str starts-with "lsm_cgroup:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM_CGROUP)
    } else if ($target | str starts-with "lsm.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "lsm:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
    } else if ($target | str starts-with "struct_ops:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_STRUCT_OPS)
        if ($target | str contains "tcp_congestion_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_TCP_CONGESTION)
        }
        if ($target | str contains "hid_bpf_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_HID_BPF)
        }
        if ($target | str contains "sched_ext_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT)
        }
        if ($target | str contains "Qdisc_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_QDISC)
        }
        if (struct-ops-target-sleepable? $target) {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "kprobe.multi:") or ($target | str starts-with "kretprobe.multi:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_KPROBE_MULTI)
    } else if ($target | str starts-with "kprobe:") or ($target | str starts-with "kretprobe:") or ($target | str starts-with "ksyscall:") or ($target | str starts-with "kretsyscall:") or ($target | str starts-with "uprobe:") or ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe:") or ($target | str starts-with "uretprobe.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        if ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "uprobe.multi:") or ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi:") or ($target | str starts-with "uretprobe.multi.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_UPROBE_MULTI)
        if ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "raw_tracepoint.w:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT_WRITABLE)
    } else if ($target | str starts-with "raw_tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
    } else if ($target | str starts-with "tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACEPOINT)
    } else if ($target | str starts-with "perf_event:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_PERF_EVENT)
    } else if ($target | str starts-with "xdp:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_XDP)
        let xdp_parts = ($target | split row ":")
        if ("devmap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DEVMAP)
        } else if ("cpumap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_CPUMAP)
        } else if ("hw" in $xdp_parts) or ("hardware" in $xdp_parts) or ("offload" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_HW)
        } else if ("drv" in $xdp_parts) or ("driver" in $xdp_parts) or ("native" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DRV)
        } else {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_SKB)
        }
        if ("frags" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_MULTI_BUFFER)
        }
    } else if ($target | str starts-with "socket_filter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCKET_FILTER)
    } else if ($target | str starts-with "tc:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_CLS)
    } else if ($target | str starts-with "tc_action:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_ACT)
    } else if ($target | str starts-with "tcx:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_TCX)
    } else if ($target | str starts-with "netkit:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_NETKIT)
    } else if ($target | str starts-with "flow_dissector:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_FLOW_DISSECTOR)
    } else if ($target | str starts-with "netfilter:") {
        $features = ($features | append $KERNEL_FEATURE_NETFILTER_LINK)
        let netfilter_parts = ($target | split row ":")
        if ("defrag" in $netfilter_parts) {
            $features = ($features | append $KERNEL_FEATURE_NETFILTER_DEFRAG)
        }
    } else if ($target | str starts-with "lwt_seg6local:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT_SEG6LOCAL)
    } else if ($target | str starts-with "lwt_in:") or ($target | str starts-with "lwt_out:") or ($target | str starts-with "lwt_xmit:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
    } else if ($target | str starts-with "sk_lookup:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_LOOKUP)
    } else if ($target | str starts-with "sk_msg:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_MSG)
    } else if ($target | str starts-with "sk_skb:") or ($target | str starts-with "sk_skb_parser:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_SKB)
    } else if ($target | str starts-with "sk_reuseport:") {
        $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_ATTACH)
        let sk_reuseport_parts = ($target | split row ":")
        if ("migrate" in $sk_reuseport_parts) {
            $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_MIGRATION)
        }
    } else if ($target | str starts-with "cgroup_skb:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SKB)
    } else if ($target | str starts-with "cgroup_sock_addr:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK_ADDR)
        let cgroup_sock_addr_hook = ($target | split row ":" | last)
        if ($cgroup_sock_addr_hook | str ends-with "_unix") {
            $features = ($features | append $KERNEL_FEATURE_ATTACH_CGROUP_UNIX_SOCK_ADDR)
        }
    } else if ($target | str starts-with "cgroup_sockopt:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCKOPT)
    } else if ($target | str starts-with "cgroup_sock:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK)
    } else if ($target | str starts-with "cgroup_device:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_DEVICE)
    } else if ($target | str starts-with "cgroup_sysctl:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SYSCTL)
    } else if ($target | str starts-with "sock_ops:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCK_OPS)
    } else if ($target | str starts-with "lirc_mode2:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LIRC_MODE2)
    } else if ($target | str starts-with "iter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_ITER)
        let iter_target = ($target | split row ":" | get 1)
        let iter_feature = (iter-target-kernel-feature $iter_target)
        if $iter_feature != null {
            $features = ($features | append $iter_feature)
        }
    } else if ($target | str starts-with "syscall:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SYSCALL)
    } else if ($target | str starts-with "freplace:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_EXTENSION)
    }

    $features
}
