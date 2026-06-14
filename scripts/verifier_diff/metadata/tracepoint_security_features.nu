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
