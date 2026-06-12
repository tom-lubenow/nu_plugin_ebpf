const IDENTITY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["setpriority"]
        fields: ["which" "who" "niceval"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getpriority"]
        fields: ["which" "who"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setregid"]
        fields: ["rgid" "egid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setreuid"]
        fields: ["ruid" "euid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setresuid"]
        fields: ["ruid" "euid" "suid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getresuid"]
        fields: ["ruidp" "euidp" "suidp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setresgid"]
        fields: ["rgid" "egid" "sgid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getresgid"]
        fields: ["rgidp" "egidp" "sgidp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setpgid"]
        fields: ["pgid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["sethostname" "gethostname" "setdomainname"]
        fields: ["name" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrlimit" "setrlimit"]
        fields: ["resource" "rlim"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrusage"]
        fields: ["who" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["prlimit64"]
        fields: ["resource" "new_rlim" "old_rlim"]
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
        syscalls: ["getcpu"]
        fields: ["cpup" "nodep" "unused"]
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
        syscalls: ["times"]
        fields: ["tbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["newuname"]
        fields: ["name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["sysinfo"]
        fields: ["info"]
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
    {
        syscalls: ["bpf"]
        fields: ["cmd" "uattr" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/bpf/syscall.c"
    }
    {
        syscalls: ["perf_event_open"]
        fields: ["attr_uptr" "group_fd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/events/core.c"
    }
    {
        syscalls: ["ptrace"]
        fields: ["request" "addr" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/ptrace.c"
    }
    {
        syscalls: ["seccomp"]
        fields: ["op" "flags" "uargs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/seccomp.c"
    }
    {
        syscalls: ["userfaultfd"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/userfaultfd.c"
    }
    {
        syscalls: ["getgroups" "setgroups"]
        fields: ["gidsetsize" "grouplist"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/groups.c"
    }
    {
        syscalls: ["capget"]
        fields: ["header" "dataptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c"
    }
    {
        syscalls: ["capset"]
        fields: ["header" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c"
    }
]
