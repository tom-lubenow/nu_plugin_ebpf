const PROCESS_SYSTEM_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["init_module"]
        fields: ["umod" "len" "uargs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c"
    }
    {
        syscalls: ["finit_module"]
        fields: ["fd" "uargs" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c"
    }
    {
        syscalls: ["delete_module"]
        fields: ["name_user" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c"
    }
    {
        syscalls: ["kexec_load"]
        fields: ["entry" "nr_segments" "segments" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kexec.c"
    }
    {
        syscalls: ["kexec_file_load"]
        fields: ["kernel_fd" "initrd_fd" "cmdline_len" "cmdline_ptr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kexec_file.c"
    }
    {
        syscalls: ["reboot"]
        fields: ["magic1" "magic2" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/reboot.c"
    }
    {
        syscalls: ["acct"]
        fields: ["name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/acct.c"
    }
]
