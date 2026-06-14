const QUOTA_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["quotactl"]
        fields: ["cmd" "special" "id" "addr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/quota/quota.c"
    }
    {
        syscalls: ["quotactl_fd"]
        fields: ["fd" "cmd" "id" "addr"]
        min_kernel: "5.14"
        source: "https://github.com/torvalds/linux/blob/v5.14/fs/quota/quota.c"
    }
]
