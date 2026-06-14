const SYSTEM_MISC_CONTROL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["sethostname" "gethostname" "setdomainname"]
        fields: ["name" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["umask"]
        fields: ["mask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["prctl"]
        fields: ["option"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrandom"]
        fields: ["buf" "count" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/drivers/char/random.c"
    }
    {
        syscalls: ["newuname"]
        fields: ["name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["personality"]
        fields: ["personality"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exec_domain.c"
    }
    {
        syscalls: ["membarrier"]
        fields: ["cmd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/membarrier.c"
    }
    {
        syscalls: ["syslog"]
        fields: ["type" "buf" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/printk/printk.c"
    }
    {
        syscalls: ["sysfs"]
        fields: ["option"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/filesystems.c"
    }
    {
        syscalls: ["rseq"]
        fields: ["rseq" "rseq_len" "flags" "sig"]
        min_kernel: "4.18"
        source: "https://github.com/torvalds/linux/blob/v4.18/kernel/rseq.c"
    }
]
