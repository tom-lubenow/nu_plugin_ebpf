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
]
