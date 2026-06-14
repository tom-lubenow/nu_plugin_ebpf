const MOUNT_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["open_tree"]
        fields: ["dfd" "filename" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    }
    {
        syscalls: ["move_mount"]
        fields: ["from_dfd" "from_pathname" "to_dfd" "to_pathname" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    }
    {
        syscalls: ["fsopen"]
        fields: ["_fs_name" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    }
    {
        syscalls: ["fsconfig"]
        fields: ["fd" "cmd" "_key" "_value" "aux"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    }
    {
        syscalls: ["fsmount"]
        fields: ["fs_fd" "flags" "attr_flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    }
    {
        syscalls: ["fspick"]
        fields: ["dfd" "path" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    }
    {
        syscalls: ["mount_setattr"]
        fields: ["dfd" "path" "flags" "uattr" "usize"]
        min_kernel: "5.12"
        source: "https://github.com/torvalds/linux/blob/v5.12/fs/namespace.c"
    }
    {
        syscalls: ["statmount"]
        fields: ["req" "buf" "bufsize" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    }
    {
        syscalls: ["listmount"]
        fields: ["req" "mnt_ids" "nr_mnt_ids" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    }
    {
        syscalls: ["open_tree_attr"]
        fields: ["dfd" "filename" "flags" "uattr" "usize"]
        min_kernel: "6.15"
        source: "https://github.com/torvalds/linux/blob/v6.15/fs/namespace.c"
    }
    {
        syscalls: ["mount"]
        fields: ["dev_name" "dir_name" "type" "flags" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    }
    {
        syscalls: ["umount"]
        fields: ["name" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    }
    {
        syscalls: ["pivot_root"]
        fields: ["new_root" "put_old"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    }
    {
        syscalls: ["ustat"]
        fields: ["dev" "ubuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
]
