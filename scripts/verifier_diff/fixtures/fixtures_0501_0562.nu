const VERIFIER_DIFF_FIXTURES_0501_0562 = [
    {
        name: "source-helper-netns-cookie-rejects-xdp"
        category: "helper-state"
        tags: [helper netns cookie program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_netns_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_netns_cookie' is only valid in socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg programs"
    }
    {
        name: "source-helper-cgroup-sysctl-raw-helpers"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl accept source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  helper-call "bpf_sysctl_get_name" $ctx $buf 16 1'
            '  helper-call "bpf_sysctl_get_current_value" $ctx $buf 16'
            '  helper-call "bpf_sysctl_get_new_value" $ctx $buf 16'
            '  helper-call "bpf_sysctl_set_new_value" $ctx $buf 1'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-invalid-name-flags"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl flags reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  helper-call "bpf_sysctl_get_name" $ctx $buf 16 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sysctl_get_name' requires arg3 flags"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-dynamic-name-flags"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl flags reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sysctl_get_name" $ctx $buf 16 $flags'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sysctl_get_name' requires arg3 flags"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-short-map-buffer"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl map-bounds reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  map-define sysctl_buf_short --kind array --value-type bytes:4 --max-entries 1'
            '  let buf = (0 | map-get sysctl_buf_short)'
            '  if $buf {'
            '    helper-call "bpf_sysctl_get_current_value" $ctx $buf 8'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper sysctl_get_current_value buf requires 8 bytes"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-dynamic-short-map-buffer"
        category: "helper-state"
        tags: [helper sysctl cgroup-sysctl map-bounds dynamic reject source metadata]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  map-define sysctl_buf_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let buf = (0 | map-get sysctl_buf_dyn_short)'
            '  if $buf {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_sysctl_get_current_value" $ctx $buf $size'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper sysctl_get_current_value buf requires 8 bytes"
    }
    {
        name: "source-helper-cgroup-sysctl-rejects-xdp"
        category: "helper-state"
        tags: [helper sysctl program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let buf = "01234567"'
            '  helper-call "bpf_sysctl_get_current_value" $ctx $buf 8'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sysctl_get_current_value' is only valid in cgroup_sysctl programs"
    }
    {
        name: "source-helper-strtox-accepts-stack-buffers"
        category: "helper-state"
        tags: [helper string parse accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  helper-call "bpf_strtol" $input 8 10 $out'
            '  helper-call "bpf_strtoul" $input 8 16 $out'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-strtox-rejects-invalid-base-flags"
        category: "helper-state"
        tags: [helper string parse flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  helper-call "bpf_strtol" $input 8 2 $out'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_strtol' requires arg2 flags to be one of 0, 8, 10, or 16"
    }
    {
        name: "source-helper-strtol-rejects-dynamic-base-flags"
        category: "helper-state"
        tags: [helper string parse flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_strtol" $input 8 $flags $out'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_strtol' requires arg2 flags to be one of 0, 8, 10, or 16"
    }
    {
        name: "source-helper-strtoul-rejects-dynamic-base-flags"
        category: "helper-state"
        tags: [helper string parse flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "12345678"'
            '  let out = "00000000"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_strtoul" $input 8 $flags $out'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_strtoul' requires arg2 flags to be one of 0, 8, 10, or 16"
    }
    {
        name: "source-helper-strtox-rejects-short-map-result"
        category: "helper-state"
        tags: [helper string parse map-bounds reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define strtox_out_short --kind array --value-type bytes:4 --max-entries 1'
            '  let input = "12345678"'
            '  let out = (0 | map-get strtox_out_short)'
            '  if $out {'
            '    helper-call "bpf_strtol" $input 8 10 $out'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strtox res requires 8 bytes"
    }
    {
        name: "source-helper-strtox-rejects-dynamic-short-map-result"
        category: "helper-state"
        tags: [helper string parse map-bounds dynamic reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define strtox_out_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let input = "12345678"'
            '  let out = (0 | map-get strtox_out_dyn_short)'
            '  if $out {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_strtol" $input $size 10 $out'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strtox res requires 8 bytes"
    }
    {
        name: "source-helper-strncmp-accepts-rodata-binary-needle"
        category: "helper-state"
        tags: [helper string compare rodata accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "abcdefgh"'
            '  helper-call "bpf_strncmp" $input 8 0x[61 62 63 64 65 66 67 68 00]'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-strncmp-accepts-captured-binary-needle"
        category: "helper-state"
        tags: [helper string compare rodata capture accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '(do {'
            '  let needle = 0x[61 62 63 64 65 66 67 68 00]'
            '  {|ctx|'
            '    let input = "abcdefgh"'
            '    helper-call "bpf_strncmp" $input 8 $needle'
            '    "pass"'
            '  }'
            '})'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-strncmp-rejects-short-map-input"
        category: "helper-state"
        tags: [helper string compare map-bounds reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define strncmp_input_short --kind array --value-type bytes:4 --max-entries 1'
            '  let input = (0 | map-get strncmp_input_short)'
            '  if $input {'
            '    helper-call "bpf_strncmp" $input 8 0x[61 62 63 64 65 66 67 68 00]'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strncmp s1 requires 8 bytes"
    }
    {
        name: "source-helper-strncmp-rejects-dynamic-short-map-input"
        category: "helper-state"
        tags: [helper string compare map-bounds dynamic reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define strncmp_input_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let input = (0 | map-get strncmp_input_dyn_short)'
            '  if $input {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_strncmp" $input $size 0x[61 62 63 64 65 66 67 68 00]'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strncmp s1 requires 8 bytes"
    }
    {
        name: "source-helper-strncmp-rejects-stack-needle"
        category: "helper-state"
        tags: [helper string compare rodata reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let input = "abcdefgh"'
            '  helper-call "bpf_strncmp" $input 8 "abcdefgh"'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper strncmp s2 expects pointer in [Map], got Stack"
    }
    {
        name: "source-helper-probe-write-user-accepts-user-dst"
        category: "helper-state"
        tags: [helper probe-write-user hazardous accept]
        default_test_lane: "dry-run"
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let dst = $ctx.arg0'
            '  if $dst {'
            '    let src = "wxyz"'
            '    helper-call "bpf_probe_write_user" $dst $src 4'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-probe-write-user-rejects-stack-dst"
        category: "helper-state"
        tags: [helper probe-write-user hazardous reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0000"'
            '  let src = "wxyz"'
            '  helper-call "bpf_probe_write_user" $dst $src 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper probe_write_user dst expects pointer in [User]"
    }
    {
        name: "source-helper-probe-write-user-rejects-zero-size"
        category: "helper-state"
        tags: [helper probe-write-user hazardous reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let dst = $ctx.arg0'
            '  if $dst {'
            '    let src = "wxyz"'
            '    helper-call "bpf_probe_write_user" $dst $src 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 36 arg2 must be > 0"
    }
    {
        name: "source-helper-probe-write-user-rejects-dynamic-size"
        category: "helper-state"
        tags: [helper probe-write-user hazardous dynamic reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let dst = $ctx.arg0'
            '  if $dst {'
            '    let src = "wxyz"'
            '    let size = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_probe_write_user" $dst $src $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 36 arg2 must be > 0"
    }
    {
        name: "source-helper-get-branch-snapshot-accepts-buffer"
        category: "helper-state"
        tags: [helper branch-stack accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = "0123456789abcdefghijklmn"'
            '  helper-call "bpf_get_branch_snapshot" $entries 24 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-branch-snapshot-accepts-zero-size-null-buffer"
        category: "helper-state"
        tags: [helper branch-stack zero-size accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_branch_snapshot" 0 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-branch-snapshot-rejects-null-nonzero-size"
        category: "helper-state"
        tags: [helper branch-stack zero-size reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_branch_snapshot" 0 24 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 176 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "source-helper-get-branch-snapshot-rejects-null-dynamic-size"
        category: "helper-state"
        tags: [helper branch-stack zero-size dynamic reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_branch_snapshot" 0 $size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 176 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "source-helper-get-branch-snapshot-rejects-nonzero-flags"
        category: "helper-state"
        tags: [helper branch-stack flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = "0123456789abcdefghijklmn"'
            '  helper-call "bpf_get_branch_snapshot" $entries 24 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_branch_snapshot' requires arg2 = 0"
    }
    {
        name: "source-helper-get-branch-snapshot-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper branch-stack flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entries = "0123456789abcdefghijklmn"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_branch_snapshot" $entries 24 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_branch_snapshot' requires arg2 = 0"
    }
    {
        name: "source-helper-read-branch-records-accepts-buffer"
        category: "helper-state"
        tags: [helper branch-stack accept]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let entries = "0123456789abcdefghijklmn"'
            '  helper-call "bpf_read_branch_records" $ctx $entries 24 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-read-branch-records-accepts-zero-size-null-buffer"
        category: "helper-state"
        tags: [helper branch-stack zero-size accept]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  helper-call "bpf_read_branch_records" $ctx 0 0 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-read-branch-records-rejects-null-nonzero-size"
        category: "helper-state"
        tags: [helper branch-stack zero-size reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  helper-call "bpf_read_branch_records" $ctx 0 8 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 119 arg1 requires arg2 = 0 when arg1 is null"
    }
    {
        name: "source-helper-read-branch-records-rejects-null-dynamic-size"
        category: "helper-state"
        tags: [helper branch-stack zero-size dynamic reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_read_branch_records" $ctx 0 $size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 119 arg1 requires arg2 = 0 when arg1 is null"
    }
    {
        name: "source-helper-read-branch-records-rejects-nonzero-reserved-flags"
        category: "helper-state"
        tags: [helper branch-stack flags reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let entries = "0123456789abcdefghijklmn"'
            '  helper-call "bpf_read_branch_records" $ctx $entries 24 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_read_branch_records' requires arg3 flags"
    }
    {
        name: "source-helper-read-branch-records-rejects-dynamic-reserved-flags"
        category: "helper-state"
        tags: [helper branch-stack flags reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let entries = "0123456789abcdefghijklmn"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_read_branch_records" $ctx $entries 24 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_read_branch_records' requires arg3 flags"
    }
    {
        name: "source-helper-read-branch-records-rejects-non-perf-event"
        category: "helper-state"
        tags: [helper branch-stack program-policy reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_read_branch_records" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_read_branch_records' is only valid in perf_event programs"
    }
    {
        name: "source-helper-get-task-stack-accepts-current-task"
        category: "helper-state"
        tags: [helper task stack-copy accept]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdefghijklmn"'
            '  helper-call "bpf_get_task_stack" $ctx.current_task $buf 24 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-task-stack-accepts-zero-size-null-buffer"
        category: "helper-state"
        tags: [helper task stack-copy zero-size accept]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_task_stack" $ctx.current_task 0 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-task-stack-rejects-null-nonzero-size"
        category: "helper-state"
        tags: [helper task stack-copy zero-size reject]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_task_stack" $ctx.current_task 0 24 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 141 arg1 requires arg2 = 0 when arg1 is null"
    }
    {
        name: "source-helper-get-task-stack-rejects-null-dynamic-size"
        category: "helper-state"
        tags: [helper task stack-copy zero-size dynamic reject]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_task_stack" $ctx.current_task 0 $size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 141 arg1 requires arg2 = 0 when arg1 is null"
    }
    {
        name: "source-helper-get-task-stack-rejects-negative-size"
        category: "helper-state"
        tags: [helper task stack-copy size reject]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdefghijklmn"'
            '  let size = (0 - 1)'
            '  helper-call "bpf_get_task_stack" $ctx.current_task $buf $size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-get-task-stack-rejects-dynamic-negative-size"
        category: "helper-state"
        tags: [helper task stack-copy size dynamic reject]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdefghijklmn"'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  helper-call "bpf_get_task_stack" $ctx.current_task $buf $size 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-get-task-stack-rejects-invalid-flags"
        category: "helper-state"
        tags: [helper task stack-copy flags reject]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdefghijklmn"'
            '  helper-call "bpf_get_task_stack" $ctx.current_task $buf 24 4096'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require flags"
    }
    {
        name: "source-helper-get-task-stack-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper task stack-copy flags reject]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdefghijklmn"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_task_stack" $ctx.current_task $buf 24 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require flags"
    }
    {
        name: "dynptr-kfunc-copy-from-user-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-copy-from-user-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_dynptr' arg0 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-copy-from-user-task-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_dynptr" $d 0 4 $ptr $ctx.current_task'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-copy-from-user-task-str-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str_dynptr" $d 0 4 $ptr $ctx.current_task'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-copy-from-user-str-accepts-user-src"
        category: "helper-state"
        tags: [kfunc copy-user source accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_str" $dst 8 $ptr 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-copy-from-user-str-rejects-stack-src"
        category: "helper-state"
        tags: [kfunc copy-user source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "abcdefgh"'
            '  kfunc-call "bpf_copy_from_user_str" $dst 8 $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_str' arg2 expects user pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-task-str-accepts-current-task"
        category: "helper-state"
        tags: [kfunc copy-user source accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str" $dst 8 $ptr $ctx.current_task 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-copy-from-user-task-str-rejects-stack-task"
        category: "helper-state"
        tags: [kfunc copy-user source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str" $dst 8 $ptr $dst 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_task_str' arg3 expects kernel pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-dynptr-rejects-stack-src"
        category: "helper-state"
        tags: [kfunc copy-user dynptr source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "abcdefgh"'
            '  kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $src'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_dynptr' arg3 expects user pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-task-dynptr-rejects-stack-task"
        category: "helper-state"
        tags: [kfunc copy-user dynptr source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_dynptr" $d 0 4 $ptr $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_task_dynptr' arg4 expects kernel pointer, got Stack"
    }
    {
        name: "source-kfunc-copy-from-user-task-str-dynptr-rejects-stack-task"
        category: "helper-state"
        tags: [kfunc copy-user dynptr source reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str_dynptr" $d 0 4 $ptr $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_task_str_dynptr' arg4 expects kernel pointer, got Stack"
    }
    {
        name: "dynptr-kfunc-from-xdp-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-copied-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-user-function-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept user-function]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def init [raw_ctx] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_xdp" $raw_ctx 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-returned-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr xdp accept user-function source metadata]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr xdp reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg2 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-packet-arg"
        category: "helper-state"
        tags: [kfunc dynptr xdp source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx.data 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg0 expects xdp_md pointer"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-nonzero-flags"
        category: "helper-state"
        tags: [kfunc dynptr xdp flags reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 1 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg1 must be known zero"
    }
    {
        name: "dynptr-kfunc-from-xdp-rejects-dynamic-flags"
        category: "helper-state"
        tags: [kfunc dynptr xdp flags reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx $flags $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' arg1 must be known zero"
    }
]
