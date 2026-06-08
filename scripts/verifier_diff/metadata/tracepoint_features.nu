const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_FD = {
    key: "tracepoint:syscalls/sys_enter_read:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_BUF = {
    key: "tracepoint:syscalls/sys_enter_read:field:buf"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_COUNT = {
    key: "tracepoint:syscalls/sys_enter_read:field:count"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_FD = {
    key: "tracepoint:syscalls/sys_enter_write:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_BUF = {
    key: "tracepoint:syscalls/sys_enter_write:field:buf"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_COUNT = {
    key: "tracepoint:syscalls/sys_enter_write:field:count"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_CLOSE_FD = {
    key: "tracepoint:syscalls/sys_enter_close:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_DFD = {
    key: "tracepoint:syscalls/sys_enter_openat:field:dfd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FILENAME = {
    key: "tracepoint:syscalls/sys_enter_openat:field:filename"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FLAGS = {
    key: "tracepoint:syscalls/sys_enter_openat:field:flags"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_MODE = {
    key: "tracepoint:syscalls/sys_enter_openat:field:mode"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_DFD = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:dfd"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_FILENAME = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:filename"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_HOW = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:how"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_USIZE = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:usize"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_FILENAME = {
    key: "tracepoint:syscalls/sys_enter_execve:field:filename"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ARGV = {
    key: "tracepoint:syscalls/sys_enter_execve:field:argv"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ENVP = {
    key: "tracepoint:syscalls/sys_enter_execve:field:envp"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
}
const FILE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["open"]
        fields: ["filename" "flags" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["creat"]
        fields: ["pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["access"]
        fields: ["filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["faccessat"]
        fields: ["dfd" "filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["faccessat2"]
        fields: ["dfd" "filename" "mode" "flags"]
        min_kernel: "5.8"
        source: "https://github.com/torvalds/linux/blob/v5.8/fs/open.c"
    }
    {
        syscalls: ["truncate" "truncate64"]
        fields: ["path" "length"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["ftruncate" "ftruncate64"]
        fields: ["fd" "length"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["chmod"]
        fields: ["filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmod"]
        fields: ["fd" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmodat"]
        fields: ["dfd" "filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmodat2"]
        fields: ["dfd" "filename" "mode" "flags"]
        min_kernel: "6.6"
        source: "https://github.com/torvalds/linux/blob/v6.6/fs/open.c"
    }
    {
        syscalls: ["chown" "lchown"]
        fields: ["filename" "user" "group"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchown"]
        fields: ["fd" "user" "group"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchownat"]
        fields: ["dfd" "filename" "user" "group" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
]

const FILE_DATA_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["pread64" "pwrite64"]
        fields: ["fd" "buf" "count" "pos"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["readv" "writev"]
        fields: ["fd" "vec" "vlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["preadv" "pwritev"]
        fields: ["fd" "vec" "vlen" "pos_l" "pos_h"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["preadv2" "pwritev2"]
        fields: ["fd" "vec" "vlen" "pos_l" "pos_h" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["sendfile" "sendfile64"]
        fields: ["out_fd" "in_fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["copy_file_range"]
        fields: ["fd_in" "off_in" "fd_out" "off_out" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["splice"]
        fields: ["fd_in" "off_in" "fd_out" "off_out" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["tee"]
        fields: ["fdin" "fdout" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["vmsplice"]
        fields: ["fd" "iov" "nr_segs" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["cachestat"]
        fields: ["fd" "cstat_range" "cstat" "flags"]
        min_kernel: "6.5"
        source: "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c"
    }
]

const SOCKET_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["socket"]
        fields: ["family" "type" "protocol"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["socketpair"]
        fields: ["family" "type" "protocol" "usockvec"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["bind"]
        fields: ["fd" "umyaddr" "addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["listen"]
        fields: ["fd" "backlog"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["accept"]
        fields: ["fd" "upeer_sockaddr" "upeer_addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["connect"]
        fields: ["fd" "uservaddr" "addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendto"]
        fields: ["fd" "buff" "len" "flags" "addr" "addr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvfrom"]
        fields: ["fd" "ubuf" "size" "flags" "addr" "addr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["accept4"]
        fields: ["fd" "upeer_sockaddr" "upeer_addrlen" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["setsockopt"]
        fields: ["fd" "level" "optname" "optval" "optlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["getsockopt"]
        fields: ["fd" "level" "optname" "optval" "optlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["getsockname" "getpeername"]
        fields: ["fd" "usockaddr" "usockaddr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["shutdown"]
        fields: ["fd" "how"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendmsg"]
        fields: ["fd" "msg" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvmsg"]
        fields: ["fd" "msg" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendmmsg"]
        fields: ["fd" "mmsg" "vlen" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvmmsg"]
        fields: ["fd" "mmsg" "vlen" "flags" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
]
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
const PROCESS_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["execveat"]
        fields: ["fd" "filename" "argv" "envp" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
    }
    {
        syscalls: ["exit" "exit_group"]
        fields: ["error_code"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["waitid"]
        fields: ["which" "upid" "infop" "options" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["wait4"]
        fields: ["upid" "stat_addr" "options" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["unshare"]
        fields: ["unshare_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["clone"]
        fields: ["clone_flags" "newsp" "parent_tidptr" "child_tidptr" "tls"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["clone3"]
        fields: ["uargs" "size"]
        min_kernel: "5.3"
        source: "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c"
    }
    {
        syscalls: ["setns"]
        fields: ["fd" "nstype"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/nsproxy.c"
    }
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
    {
        syscalls: ["set_tid_address"]
        fields: ["tidptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["kcmp"]
        fields: ["pid1" "pid2" "type" "idx1" "idx2"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c"
    }
]
const FD_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["lseek"]
        fields: ["fd" "offset" "whence"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["fadvise64"]
        fields: ["fd" "offset" "len" "advice"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/fadvise.c"
    }
    {
        syscalls: ["readahead"]
        fields: ["fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/readahead.c"
    }
    {
        syscalls: ["fallocate"]
        fields: ["fd" "mode" "offset" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["syncfs" "fsync" "fdatasync"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["sync_file_range"]
        fields: ["fd" "offset" "nbytes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["fcntl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fcntl.c"
    }
    {
        syscalls: ["flock"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/locks.c"
    }
    {
        syscalls: ["ioctl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/ioctl.c"
    }
    {
        syscalls: ["dup"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup2"]
        fields: ["oldfd" "newfd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup3"]
        fields: ["oldfd" "newfd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["pipe"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["pipe2"]
        fields: ["fildes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["eventfd"]
        fields: ["count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["eventfd2"]
        fields: ["count" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["close_range"]
        fields: ["fd" "max_fd" "flags"]
        min_kernel: "5.9"
        source: "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    }
    {
        syscalls: ["epoll_create"]
        fields: ["size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_create1"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_ctl"]
        fields: ["epfd" "op" "fd" "event"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_wait"]
        fields: ["epfd" "events" "maxevents" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_pwait"]
        fields: ["epfd" "events" "maxevents" "timeout" "sigmask" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_pwait2"]
        fields: ["epfd" "events" "maxevents" "timeout" "sigmask" "sigsetsize"]
        min_kernel: "5.11"
        source: "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c"
    }
    {
        syscalls: ["inotify_init1"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["inotify_add_watch"]
        fields: ["fd" "pathname" "mask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["inotify_rm_watch"]
        fields: ["fd" "wd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["fanotify_init"]
        fields: ["flags" "event_f_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c"
    }
    {
        syscalls: ["fanotify_mark"]
        fields: ["fanotify_fd" "flags" "mask" "dfd" "pathname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c"
    }
    {
        syscalls: ["poll"]
        fields: ["ufds" "nfds" "timeout_msecs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["ppoll"]
        fields: ["ufds" "nfds" "tsp" "sigmask" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["select"]
        fields: ["n" "inp" "outp" "exp" "tvp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["pselect6"]
        fields: ["n" "inp" "outp" "exp" "tsp" "sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
]
const MM_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["brk"]
        fields: ["brk"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["mmap"]
        fields: ["addr" "len" "prot" "flags" "fd" "off"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/sys_x86_64.c"
    }
    {
        syscalls: ["mmap_pgoff"]
        fields: ["addr" "len" "prot" "flags" "fd" "pgoff"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["munmap"]
        fields: ["addr" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["remap_file_pages"]
        fields: ["start" "size" "prot" "pgoff" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["mprotect"]
        fields: ["start" "len" "prot"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_mprotect"]
        fields: ["start" "len" "prot" "pkey"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_alloc"]
        fields: ["flags" "init_val"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_free"]
        fields: ["pkey"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["mremap"]
        fields: ["addr" "old_len" "new_len" "flags" "new_addr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mremap.c"
    }
    {
        syscalls: ["madvise"]
        fields: ["start" "len_in" "behavior"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/madvise.c"
    }
    {
        syscalls: ["process_vm_readv" "process_vm_writev"]
        fields: ["lvec" "liovcnt" "rvec" "riovcnt" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/process_vm_access.c"
    }
    {
        syscalls: ["process_madvise"]
        fields: ["pidfd" "vec" "vlen" "behavior" "flags"]
        min_kernel: "5.10"
        source: "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c"
    }
    {
        syscalls: ["process_mrelease"]
        fields: ["pidfd" "flags"]
        min_kernel: "5.15"
        source: "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c"
    }
    {
        syscalls: ["mlock" "munlock"]
        fields: ["start" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mlock2"]
        fields: ["start" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mlockall"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mincore"]
        fields: ["start" "len" "vec"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mincore.c"
    }
    {
        syscalls: ["msync"]
        fields: ["start" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/msync.c"
    }
    {
        syscalls: ["mseal"]
        fields: ["start" "len" "flags"]
        min_kernel: "6.10"
        source: "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c"
    }
    {
        syscalls: ["munlockall"]
        fields: []
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["swapon"]
        fields: ["specialfile" "swap_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c"
    }
    {
        syscalls: ["swapoff"]
        fields: ["specialfile"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c"
    }
    {
        syscalls: ["memfd_create"]
        fields: ["uname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/shmem.c"
    }
    {
        syscalls: ["memfd_secret"]
        fields: ["flags"]
        min_kernel: "5.14"
        source: "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c"
    }
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
const TIME_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["utime"]
        fields: ["filename" "times"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["utimes"]
        fields: ["filename" "utimes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["futimesat"]
        fields: ["dfd" "filename" "utimes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["utimensat"]
        fields: ["dfd" "filename" "utimes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["time"]
        fields: ["tloc"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["gettimeofday" "settimeofday"]
        fields: ["tv" "tz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["adjtimex"]
        fields: ["txc_p"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["alarm"]
        fields: ["seconds"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c"
    }
    {
        syscalls: ["getitimer"]
        fields: ["which" "value"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c"
    }
    {
        syscalls: ["setitimer"]
        fields: ["which" "value" "ovalue"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c"
    }
    {
        syscalls: ["nanosleep"]
        fields: ["rqtp" "rmtp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/hrtimer.c"
    }
    {
        syscalls: ["timer_create"]
        fields: ["which_clock" "timer_event_spec" "created_timer_id"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_gettime"]
        fields: ["timer_id" "setting"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_getoverrun" "timer_delete"]
        fields: ["timer_id"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_settime"]
        fields: ["timer_id" "flags" "new_setting" "old_setting"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_settime" "clock_gettime" "clock_getres"]
        fields: ["which_clock" "tp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_adjtime"]
        fields: ["which_clock" "utx"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_nanosleep"]
        fields: ["which_clock" "flags" "rqtp" "rmtp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timerfd_create"]
        fields: ["clockid" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
    {
        syscalls: ["timerfd_settime"]
        fields: ["ufd" "flags" "utmr" "otmr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
    {
        syscalls: ["timerfd_gettime"]
        fields: ["ufd" "otmr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
]
const IO_URING_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["io_uring_setup"]
        fields: ["entries" "params"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
    {
        syscalls: ["io_uring_enter"]
        fields: ["fd" "to_submit" "min_complete" "flags" "sig" "sigsz"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
    {
        syscalls: ["io_uring_register"]
        fields: ["fd" "opcode" "nr_args"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
]
const AIO_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["io_setup"]
        fields: ["nr_events" "ctxp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_destroy"]
        fields: ["ctx"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_submit"]
        fields: ["ctx_id" "nr" "iocbpp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_cancel"]
        fields: ["ctx_id" "iocb" "result"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_getevents"]
        fields: ["ctx_id" "min_nr" "nr" "events" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_pgetevents"]
        fields: ["ctx_id" "min_nr" "nr" "events" "timeout" "usig"]
        min_kernel: "4.18"
        source: "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c"
    }
]
const IOPRIO_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["ioprio_set"]
        fields: ["which" "who" "ioprio"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c"
    }
    {
        syscalls: ["ioprio_get"]
        fields: ["which" "who"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c"
    }
]
const KEY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["add_key"]
        fields: ["_type" "_description" "_payload" "plen" "ringid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c"
    }
    {
        syscalls: ["request_key"]
        fields: ["_type" "_description" "_callout_info" "destringid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c"
    }
    {
        syscalls: ["keyctl"]
        fields: ["option"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c"
    }
]
const SIGNAL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["rt_sigprocmask"]
        fields: ["how" "nset" "oset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigpending"]
        fields: ["uset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigtimedwait"]
        fields: ["uthese" "uinfo" "uts" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["kill" "tkill"]
        fields: ["sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["tgkill"]
        fields: ["sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigqueueinfo"]
        fields: ["sig" "uinfo"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_tgsigqueueinfo"]
        fields: ["sig" "uinfo"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["sigaltstack"]
        fields: ["uss" "uoss"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigaction"]
        fields: ["sig" "act" "oact" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigsuspend"]
        fields: ["unewset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["signalfd"]
        fields: ["ufd" "user_mask" "sizemask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c"
    }
    {
        syscalls: ["signalfd4"]
        fields: ["ufd" "user_mask" "sizemask" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c"
    }
    {
        syscalls: ["pidfd_send_signal"]
        fields: ["pidfd" "sig" "info" "flags"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c"
    }
    {
        syscalls: ["pidfd_open"]
        fields: ["flags"]
        min_kernel: "5.3"
        source: "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c"
    }
    {
        syscalls: ["pidfd_getfd"]
        fields: ["pidfd" "fd" "flags"]
        min_kernel: "5.6"
        source: "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c"
    }
]
const LANDLOCK_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["landlock_create_ruleset"]
        fields: ["attr" "size" "flags"]
        min_kernel: "5.13"
        source: "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    }
    {
        syscalls: ["landlock_add_rule"]
        fields: ["ruleset_fd" "rule_type" "rule_attr" "flags"]
        min_kernel: "5.13"
        source: "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    }
    {
        syscalls: ["landlock_restrict_self"]
        fields: ["ruleset_fd" "flags"]
        min_kernel: "5.13"
        source: "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    }
]
const LSM_SYSCALL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["lsm_get_self_attr"]
        fields: ["attr" "ctx" "size" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    }
    {
        syscalls: ["lsm_set_self_attr"]
        fields: ["attr" "ctx" "size" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    }
    {
        syscalls: ["lsm_list_modules"]
        fields: ["ids" "size" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    }
]
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
const SCHED_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["nice"]
        fields: ["increment"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setscheduler"]
        fields: ["policy" "param"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setparam" "sched_getparam"]
        fields: ["param"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setattr"]
        fields: ["uattr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_getattr"]
        fields: ["uattr" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setaffinity" "sched_getaffinity"]
        fields: ["len" "user_mask_ptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_get_priority_max" "sched_get_priority_min"]
        fields: ["policy"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_rr_get_interval"]
        fields: ["interval"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
]
const FUTEX_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["futex"]
        fields: ["uaddr" "op" "val" "utime" "uaddr2" "val3"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
    {
        syscalls: ["futex_waitv"]
        fields: ["waiters" "nr_futexes" "flags" "timeout" "clockid"]
        min_kernel: "5.16"
        source: "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_wake"]
        fields: ["uaddr" "mask" "nr" "flags"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_wait"]
        fields: ["uaddr" "val" "mask" "flags" "timeout" "clockid"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_requeue"]
        fields: ["waiters" "flags" "nr_wake" "nr_requeue"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["set_robust_list"]
        fields: ["head" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
    {
        syscalls: ["get_robust_list"]
        fields: ["head_ptr" "len_ptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
]
const MQUEUE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["mq_open"]
        fields: ["u_name" "oflag" "mode" "u_attr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_unlink"]
        fields: ["u_name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_timedsend"]
        fields: ["mqdes" "u_msg_ptr" "msg_len" "msg_prio" "u_abs_timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_timedreceive"]
        fields: ["mqdes" "u_msg_ptr" "msg_len" "u_msg_prio" "u_abs_timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_notify"]
        fields: ["mqdes" "u_notification"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_getsetattr"]
        fields: ["mqdes" "u_mqstat" "u_omqstat"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
]
const IPC_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["msgget"]
        fields: ["key" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgctl"]
        fields: ["msqid" "cmd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgsnd"]
        fields: ["msqid" "msgp" "msgsz" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgrcv"]
        fields: ["msqid" "msgp" "msgsz" "msgtyp" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["semget"]
        fields: ["key" "nsems" "semflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semctl"]
        fields: ["semid" "semnum" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semtimedop"]
        fields: ["semid" "tsops" "nsops" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semop"]
        fields: ["semid" "tsops" "nsops"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["shmget"]
        fields: ["key" "size" "shmflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmctl"]
        fields: ["shmid" "cmd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmat"]
        fields: ["shmid" "shmaddr" "shmflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmdt"]
        fields: ["shmaddr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
]
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
const TRACEPOINT_FIELD_KERNEL_FEATURES = [
    { target: "tracepoint:syscalls/sys_enter_read" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_FD }
    { target: "tracepoint:syscalls/sys_enter_read" field: "buf" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_BUF }
    { target: "tracepoint:syscalls/sys_enter_read" field: "count" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_COUNT }
    { target: "tracepoint:syscalls/sys_enter_write" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_FD }
    { target: "tracepoint:syscalls/sys_enter_write" field: "buf" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_BUF }
    { target: "tracepoint:syscalls/sys_enter_write" field: "count" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_COUNT }
    { target: "tracepoint:syscalls/sys_enter_close" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_CLOSE_FD }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "dfd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_DFD }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "flags" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FLAGS }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "mode" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_MODE }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "dfd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_DFD }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "how" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_HOW }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "usize" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_USIZE }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "argv" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ARGV }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "envp" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ENVP }
]
