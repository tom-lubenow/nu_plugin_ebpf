const PATH_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["chdir" "chroot"]
        fields: ["filename"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchdir"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["getcwd"]
        fields: ["buf" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/dcache.c"
    }
    {
        syscalls: ["readlink"]
        fields: ["path" "buf" "bufsiz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["readlinkat"]
        fields: ["dfd" "pathname" "buf" "bufsiz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["statfs"]
        fields: ["pathname" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
    {
        syscalls: ["fstatfs"]
        fields: ["fd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
    {
        syscalls: ["getdents" "getdents64"]
        fields: ["fd" "dirent" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/readdir.c"
    }
    {
        syscalls: ["name_to_handle_at"]
        fields: ["dfd" "name" "handle" "mnt_id" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c"
    }
    {
        syscalls: ["open_by_handle_at"]
        fields: ["mountdirfd" "handle" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c"
    }
    {
        syscalls: ["stat" "lstat" "newstat" "newlstat" "stat64" "lstat64"]
        fields: ["filename" "statbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["fstat" "newfstat" "fstat64"]
        fields: ["fd" "statbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["newfstatat" "fstatat64"]
        fields: ["dfd" "filename" "statbuf" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["statx"]
        fields: ["dfd" "filename" "flags" "mask" "buffer"]
        min_kernel: "4.11"
        source: "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c"
    }
    {
        syscalls: ["file_getattr" "file_setattr"]
        fields: ["dfd" "filename" "ufattr" "usize" "at_flags"]
        min_kernel: "6.17"
        source: "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c"
    }
    {
        syscalls: ["mknod"]
        fields: ["filename" "mode" "dev"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mknodat"]
        fields: ["dfd" "filename" "mode" "dev"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mkdir"]
        fields: ["pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mkdirat"]
        fields: ["dfd" "pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["rmdir" "unlink"]
        fields: ["pathname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["unlinkat"]
        fields: ["dfd" "pathname" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["symlink" "link" "rename"]
        fields: ["oldname" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["symlinkat"]
        fields: ["oldname" "newdfd" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["linkat"]
        fields: ["olddfd" "oldname" "newdfd" "newname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["renameat"]
        fields: ["olddfd" "oldname" "newdfd" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["renameat2"]
        fields: ["olddfd" "oldname" "newdfd" "newname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
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
