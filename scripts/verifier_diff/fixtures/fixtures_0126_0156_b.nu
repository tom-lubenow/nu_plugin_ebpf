const VERIFIER_DIFF_FIXTURES_0126_0156_B = [
    {
        name: "tracepoint-landlock-create-ruleset-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_create_ruleset]
        target: "tracepoint:syscalls/sys_enter_landlock_create_ruleset"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr'
            '  if $attr { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-add-rule-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_add_rule]
        target: "tracepoint:syscalls/sys_enter_landlock_add_rule"
        program: [
            '{|ctx|'
            '  let rule_attr = $ctx.rule_attr'
            '  if $rule_attr { 1 | count }'
            '  ($ctx.ruleset_fd + $ctx.rule_type + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-landlock-restrict-self-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_landlock_restrict_self]
        target: "tracepoint:syscalls/sys_enter_landlock_restrict_self"
        program: [
            '{|ctx|'
            '  ($ctx.ruleset_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-get-self-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_get_self_attr]
        target: "tracepoint:syscalls/sys_enter_lsm_get_self_attr"
        program: [
            '{|ctx|'
            '  let lsm_ctx = $ctx.ctx'
            '  let size = $ctx.size'
            '  if $lsm_ctx { 1 | count }'
            '  if $size { 1 | count }'
            '  ($ctx.attr + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-set-self-attr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_set_self_attr]
        target: "tracepoint:syscalls/sys_enter_lsm_set_self_attr"
        program: [
            '{|ctx|'
            '  let lsm_ctx = $ctx.ctx'
            '  if $lsm_ctx { 1 | count }'
            '  ($ctx.attr + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-lsm-list-modules-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_lsm_list_modules]
        target: "tracepoint:syscalls/sys_enter_lsm_list_modules"
        program: [
            '{|ctx|'
            '  let ids = $ctx.ids'
            '  let size = $ctx.size'
            '  if $ids { 1 | count }'
            '  if $size { 1 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setresuid-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setresuid"
        program: [
            '{|ctx|'
            '  ($ctx.ruid + $ctx.euid + $ctx.suid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getresgid-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_getresgid"
        program: [
            '{|ctx|'
            '  let rgidp = $ctx.rgidp'
            '  let egidp = $ctx.egidp'
            '  let sgidp = $ctx.sgidp'
            '  if $rgidp { 1 | count }'
            '  if $egidp { 1 | count }'
            '  if $sgidp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setgroups-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setgroups"
        program: [
            '{|ctx|'
            '  $ctx.gidsetsize | count'
            '  let grouplist = $ctx.grouplist'
            '  if $grouplist { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-capset-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_capset"
        program: [
            '{|ctx|'
            '  let header = $ctx.header'
            '  let data = $ctx.data'
            '  if $header { 1 | count }'
            '  if $data { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-prctl-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_prctl"
        program: [
            '{|ctx|'
            '  ($ctx.option + ($ctx.args | get 1)) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-setscheduler-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_setscheduler]
        target: "tracepoint:syscalls/sys_enter_sched_setscheduler"
        program: [
            '{|ctx|'
            '  $ctx.policy | count'
            '  let param = $ctx.param'
            '  if $param { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-setaffinity-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_setaffinity]
        target: "tracepoint:syscalls/sys_enter_sched_setaffinity"
        program: [
            '{|ctx|'
            '  $ctx.len | count'
            '  let mask = $ctx.user_mask_ptr'
            '  if $mask { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-getattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_getattr]
        target: "tracepoint:syscalls/sys_enter_sched_getattr"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.flags) | count'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sched-rr-get-interval-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sched_rr_get_interval]
        target: "tracepoint:syscalls/sys_enter_sched_rr_get_interval"
        program: [
            '{|ctx|'
            '  let interval = $ctx.interval'
            '  if $interval { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-nice-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_nice]
        target: "tracepoint:syscalls/sys_enter_nice"
        program: [
            '{|ctx|'
            '  $ctx.increment | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
