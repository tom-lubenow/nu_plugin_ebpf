const X86_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["arch_prctl"]
        fields: ["option"]
        min_kernel: "5.0"
        source: "https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/process_64.c"
    }
    {
        syscalls: ["ioperm"]
        fields: ["from" "num" "turn_on"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    }
    {
        syscalls: ["iopl"]
        fields: ["level"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    }
    {
        syscalls: ["modify_ldt"]
        fields: ["func" "ptr" "bytecount"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ldt.c"
    }
    {
        syscalls: ["map_shadow_stack"]
        fields: ["addr" "size" "flags"]
        min_kernel: "6.6"
        source: "https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/shstk.c"
    }
]
