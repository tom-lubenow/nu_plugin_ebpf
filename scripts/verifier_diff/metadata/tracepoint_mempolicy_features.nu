const MEMPOLICY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["mbind"]
        fields: ["start" "len" "mode" "nmask" "maxnode" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["set_mempolicy"]
        fields: ["mode" "nmask" "maxnode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["get_mempolicy"]
        fields: ["policy" "nmask" "maxnode" "addr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["migrate_pages"]
        fields: ["maxnode" "old_nodes" "new_nodes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["move_pages"]
        fields: ["nr_pages" "pages" "nodes" "status" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/migrate.c"
    }
    {
        syscalls: ["set_mempolicy_home_node"]
        fields: ["start" "len" "home_node" "flags"]
        min_kernel: "5.17"
        source: "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c"
    }
]
