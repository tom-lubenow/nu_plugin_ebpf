const PATH_XATTR_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["setxattr" "lsetxattr"]
        fields: ["pathname" "name" "value" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["fsetxattr"]
        fields: ["fd" "name" "value" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["getxattr" "lgetxattr"]
        fields: ["pathname" "name" "value" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["fgetxattr"]
        fields: ["fd" "name" "value" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["listxattr" "llistxattr"]
        fields: ["pathname" "list" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["flistxattr"]
        fields: ["fd" "list" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["removexattr" "lremovexattr"]
        fields: ["pathname" "name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["fremovexattr"]
        fields: ["fd" "name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["setxattrat" "getxattrat"]
        fields: ["dfd" "pathname" "at_flags" "name" "uargs" "usize"]
        min_kernel: "6.13"
        source: "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    }
    {
        syscalls: ["listxattrat"]
        fields: ["dfd" "pathname" "at_flags" "list" "size"]
        min_kernel: "6.13"
        source: "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    }
    {
        syscalls: ["removexattrat"]
        fields: ["dfd" "pathname" "at_flags" "name"]
        min_kernel: "6.13"
        source: "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    }
]

let PATH_XATTR_MOUNT_TRACEPOINT_FIELD_SPECS = (
    $PATH_XATTR_TRACEPOINT_FIELD_SPECS
    | append $MOUNT_TRACEPOINT_FIELD_SPECS
)
