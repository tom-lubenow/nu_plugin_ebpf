const VERIFIER_DIFF_FIXTURES_0501_1000 = [
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
    {
        name: "dynptr-kfunc-from-xdp-rejects-non-xdp-program"
        category: "helper-state"
        tags: [kfunc dynptr xdp program-policy reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_xdp" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_xdp' is only valid in xdp programs"
    }
    {
        name: "dynptr-kfunc-from-skb-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-copied-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept context-alias]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-user-function-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept user-function]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def init [raw_ctx] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
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
        name: "dynptr-kfunc-from-skb-returned-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept user-function source metadata]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-user-function-out-param"
        category: "helper-state"
        tags: [kfunc dynptr skb tc accept user-function]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def init [raw_ctx d] {'
            '    kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '    0'
            '  }'
            '  def size [d] {'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  let d = "0123456789abcdef"'
            '  init $ctx $d'
            '  size $d'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-reinit-after-conditional-user-function-init"
        category: "helper-state"
        tags: [kfunc dynptr skb tc reject user-function branch]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def maybe-init [raw_ctx d selector] {'
            '    if $selector == 0 {'
            '      kfunc-call "bpf_dynptr_from_skb" $raw_ctx 0 $d'
            '    }'
            '    0'
            '  }'
            '  let d = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  maybe-init $ctx $d $selector'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-netfilter-skb-pointer"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter accept]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.skb 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-netfilter-copied-skb-pointer"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter accept context-alias]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  let skb = $ctx.skb'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-netfilter-user-function-skb-pointer"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter accept user-function]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  def init [skb] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx.skb'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-tracing-skb-argument"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing accept]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.arg0 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-tracing-copied-skb-argument"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing accept context-alias]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let skb = $ctx.arg0'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-accepts-tracing-user-function-skb-argument"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing accept user-function]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  def init [skb] {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_dynptr_from_skb" $skb 0 $d'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '    0'
            '  }'
            '  init $ctx.arg0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-packet-arg"
        category: "helper-state"
        tags: [kfunc dynptr skb tc source reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.data 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-netfilter-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb netfilter source reject]
        requires: [kernel-btf]
        target: "netfilter:ipv4:pre_routing"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-tracing-raw-context"
        category: "helper-state"
        tags: [kfunc dynptr skb tracing source reject]
        requires: [kernel-btf]
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr skb tc reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg2 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-nonzero-flags"
        category: "helper-state"
        tags: [kfunc dynptr skb tc flags reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 1 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg1 must be known zero"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-dynamic-flags"
        category: "helper-state"
        tags: [kfunc dynptr skb tc flags reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx $flags $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' arg1 must be known zero"
    }
    {
        name: "dynptr-kfunc-from-skb-rejects-non-skb-program"
        category: "helper-state"
        tags: [kfunc dynptr skb program-policy reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_from_skb' is only valid in socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser, netfilter, fentry, fexit, fmod_ret, and tp_btf programs"
    }
    {
        name: "dynptr-kfunc-size-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-size-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_size" $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-record-field-local-tracks-lifecycle"
        category: "helper-state"
        tags: [kfunc dynptr record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { d: "0123456789abcdef" }'
            '  let d = $rec.d'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-record-field-direct-tracks-lifecycle"
        category: "helper-state"
        tags: [kfunc dynptr record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { d: "0123456789abcdef" }'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $rec.d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $rec.d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $rec.d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rejects-nonzero-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 1 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-allows-zero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 0'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rejects-nonzero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 1'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rejects-dynamic-size"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 $size)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg3 must be known constant"
    }
    {
        name: "dynptr-kfunc-slice-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 4)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-nonzero-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 1 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-allows-zero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 0'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-nonzero-vreg-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let buf = 1'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 $buf 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-dynamic-size"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 $size)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg3 must be known constant"
    }
    {
        name: "dynptr-kfunc-adjust-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_adjust" $d 0 4'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-adjust-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_adjust" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_adjust' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-memset-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_memset" $d 0 0 4'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-memset-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_memset" $d 0 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_memset' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-null-rdonly-queries-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let is_null = (kfunc-call "bpf_dynptr_is_null" $d)'
            '  let is_rdonly = (kfunc-call "bpf_dynptr_is_rdonly" $d)'
            '  $is_null | count'
            '  $is_rdonly | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-copy-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_clone" $dst $src'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_submit_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-copy-rejects-uninitialized-destination"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_copy' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-copy-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_discard_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_copy' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-initializes-destination"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  let size = (kfunc-call "bpf_dynptr_size" $clone)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-clone-rejects-same-stack-slot"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 must reference distinct stack slot from arg0"
    }
    {
        name: "dynptr-kfunc-clone-rejects-initialized-destination"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let src = "0123456789abcdef"'
            '  let dst = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_clone" $src $dst'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  helper-call "bpf_ringbuf_discard_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-clone-rejects-destination-initialized-on-one-path"
        category: "helper-state"
        tags: [kfunc dynptr branch reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let src = "0123456789abcdef"'
            '  let dst = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  }'
            '  kfunc-call "bpf_dynptr_clone" $src $dst'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-clone-submit-through-clone-balanced"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $clone 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-kfunc-clone-submit-through-clone-invalidates-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $clone 0'
            '  kfunc-call "bpf_dynptr_size" $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-discard-invalidates-clone"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "stackid-built-in-kstacks"
        category: "maps"
        tags: [helper-call stack-trace reserved-name]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_stackid" $ctx kstacks 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stackid-built-in-kstacks-rejects-dynamic-flags"
        category: "maps"
        tags: [helper-call stack-trace reserved-name flags reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_stackid" $ctx kstacks $flags | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stackid' requires arg2 flags"
    }
    {
        name: "stackid-context-fields"
        category: "context-surface"
        tags: [context stack-trace kstack ustack accept]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.kstack + $ctx.ustack) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-bound-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "helper-current-task-bound-projection"
        category: "context-surface"
        tags: [context task helper-call source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  $task.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "current-cgroup-bound-context"
        category: "context-surface"
        tags: [context cgroup btf source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let cg = $ctx.current_cgroup'
            '  $cg.kn.id | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-scalar-mut"
        category: "globals"
        tags: [data-global scalar]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = 0'
            '  $hits = ($hits + 1)'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-cgroup-array-contains"
        category: "packet"
        tags: [tc-action cgroup-array helper-policy]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-coarse-time-context"
        category: "context-surface"
        tags: [tc context time source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.ktime_coarse | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-cgroup-array-contains"
        category: "packet"
        tags: [xdp cgroup-array helper-policy]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context"
        category: "context-surface"
        tags: [tc-action context packet]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-rich-metadata-context"
        category: "context-surface"
        tags: [tc-action context packet source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.wire_len + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.tstamp + $ctx.tstamp_type + $ctx.hwtstamp + $ctx.cb.0) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable record source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-upsert-write"
        category: "context-surface"
        tags: [tc-action context packet writable record upsert source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-upsert"
        category: "context-surface"
        tags: [tc context socket record upsert source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | upsert socket $ctx.sk)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-preserve"
        category: "context-surface"
        tags: [tc context socket record upsert preserve source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ($base | upsert ok true)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-pipeline-shape"
        category: "context-surface"
        tags: [tc context socket record merge select reject rename source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk, keep: 1 } | merge { ok: true } | select socket ok | reject ok | rename sock)'
            '  $rec.sock.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-default-field"
        category: "context-surface"
        tags: [tc context socket record default source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default $ctx.sk socket)'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-spread-pipeline-rename"
        category: "context-surface"
        tags: [tc context socket record spread rename source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ({ ...$base } | rename sock)'
            '  $rec.sock.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-get-root"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  let sk = ($rec | get socket)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-get-chain"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-rename-get-chain"
        category: "context-surface"
        tags: [tc context socket record rename get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { ok: true, socket: $ctx.sk }'
            '  $rec | rename keep sock | get sock | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-socket-context-wrapper-get-chain"
        category: "context-surface"
        tags: [tc context socket record wrapper get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { socket: $sock } }'
            '  wrap $ctx.sk | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-insert-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline insert get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | insert socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-rename-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline rename get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: ($ctx | get sk) } | rename sock)'
            '  $rec | get sock | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-merge-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline merge get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | merge { socket: ($ctx | get sk) })'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-default-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline default get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default ($ctx | get sk) socket)'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-update-context-get-root"
        category: "context-surface"
        tags: [tc context socket record pipeline update get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk } | update socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-scalar"
        category: "context-surface"
        tags: [tc context get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get packet_len | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-packet-data-read"
        category: "context-surface"
        tags: [tc context packet get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get data | get 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-socket-chain"
        category: "context-surface"
        tags: [tc context socket get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-context-get-socket-bound-root"
        category: "context-surface"
        tags: [tc context socket get alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = ($ctx | get sk)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-context-get-root"
        category: "context-surface"
        tags: [tc context socket record get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx | get sk) }'
            '  $rec.socket.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-context-get-root"
        category: "context-surface"
        tags: [tc context socket user-function get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [c] { $c | get sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-context-get-root"
        category: "context-surface"
        tags: [tc context socket record user-function get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [c] { { socket: ($c | get sk) } }'
            '  wrap $ctx | get socket | get family | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-context-get-scalar"
        category: "context-surface"
        tags: [tc context user-function get source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_packet [event] {'
            '    $event | get packet_len | count'
            '    0'
            '  }'
            '  read_packet $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-context-get-bound-socket"
        category: "context-surface"
        tags: [tc context socket user-function get alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [event] {'
            '    let sk = ($event | get sk)'
            '    $sk | get family | count'
            '    0'
            '  }'
            '  read_family $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-spread-write"
        category: "context-surface"
        tags: [tc-action context packet writable record spread source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-user-function-record-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable record user-function source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-context-socket-write"
        category: "context-surface"
        tags: [tc-action context writable socket source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-record-context-socket-write"
        category: "context-surface"
        tags: [tc-action context writable socket record source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sk = 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-helper-backed-socket-projections"
        category: "context-surface"
        tags: [tc context socket helper-backed]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  ($ctx.sk.tcp.snd_cwnd + $ctx.sk.full.family + $ctx.sk.listener.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-bound-socket-projection"
        category: "context-surface"
        tags: [tc context socket user-function source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [sk] {'
            '    $sk.family | count'
            '    0'
            '  }'
            '  let sk = $ctx.sk'
            '  let seen = (read_family $sk)'
            '  $seen | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-ingress-skb-context-write"
        category: "context-surface"
        tags: [tc context packet writable]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable alias source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable alias get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = ($ctx | get data)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-upsert-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline upsert get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-insert-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline insert get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-merge-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline merge get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { data: ($ctx | get data) })'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-default-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline default get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get data) data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-update-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline update get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: null } | update data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-pipeline-select-reject-rename-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record pipeline select reject rename get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: ($ctx | get data), keep: 1 } | select data keep | reject keep | rename packet)'
            '  $rec.packet.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable user-function alias source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event.data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable user-function alias get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event | get data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-packet-header-alias-write"
        category: "context-surface"
        tags: [tc context packet writable packet-header alias source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.eth.h_proto = 0x86dd'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-phi-joined-packet-data-read"
        category: "context-surface"
        tags: [tc context packet phi accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let selector = $ctx.mark'
            '  let data = (if $selector == 0 { $ctx.data } else { $ctx.data })'
            '  if ($ctx.data_end != 0) {'
            '    ($data | get 0) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: ($ctx | get data) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-identity-get-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record identity-wrapper get source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  mut rec = { data: (id ($ctx | get data)) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-spread-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable record spread source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-packet-data-write"
        category: "context-surface"
        tags: [tc context packet writable user-function record source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  let data = $ctx.data'
            '  mut rec = (wrap $data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: $ctx.data_meta }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: ($ctx | get data_meta) }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-pipeline-upsert-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record pipeline upsert get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert meta ($ctx | get data_meta))'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-bound-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable alias get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut meta = ($ctx | get data_meta)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-record-spread-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable record spread source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let base = { meta: $ctx.data_meta }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-user-function-record-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable user-function record source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def wrap [meta] { { meta: $meta } }'
            '  let meta = $ctx.data_meta'
            '  mut rec = (wrap $meta)'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-user-function-returned-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable user-function alias source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event.data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-user-function-returned-get-data-meta-write"
        category: "context-surface"
        tags: [xdp context packet writable user-function alias get source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event | get data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-egress-rejects-context-socket-write"
        category: "context-policy"
        tags: [tc context writable socket reject egress-only]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs"
    }
    {
        name: "tc-skb-get-xfrm-state-helper"
        category: "helper-state"
        tags: [tc helper xfrm accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-get-xfrm-state-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper xfrm flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"
    }
    {
        name: "tc-skb-vlan-push-helper"
        category: "helper-state"
        tags: [tc helper vlan accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-vlan-pop-helper"
        category: "helper-state"
        tags: [tc helper vlan accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_pop" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-vlan-push-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper vlan packet-bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-vlan-push-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper vlan packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_vlan_push" $ctx 33024 1'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-proto-helper"
        category: "helper-state"
        tags: [tc helper skb-change accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-proto-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_proto' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-proto-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_proto" $ctx 34525 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_proto' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-tail-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper skb-change packet-bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_skb_change_tail" $ctx 64 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-change-tail-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper skb-change packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_tail" $ctx 64 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-change-tail-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_tail" $ctx 64 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_tail' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-head-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_head" $ctx 14 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_head' requires arg2 = 0"
    }
    {
        name: "tc-skb-change-head-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_change_head" $ctx 14 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_change_head' requires arg2 = 0"
    }
    {
        name: "tc-skb-adjust-room-helper"
        category: "helper-state"
        tags: [tc helper skb-change accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_adjust_room" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-adjust-room-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper skb-change flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_adjust_room" $ctx 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_adjust_room' requires arg3 flags"
    }
    {
        name: "tc-skb-change-type-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_change_type" $ctx 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-ecn-set-ce-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_ecn_set_ce" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tstamp-helper"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tstamp-rejects-invalid-type"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg2"
    }
    {
        name: "tc-skb-set-tstamp-rejects-dynamic-type"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let tstype = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 $tstype'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg2"
    }
    {
        name: "tc-skb-set-tstamp-rejects-unspec-nonzero-tstamp"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_set_tstamp" $ctx 123 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
    }
    {
        name: "tc-skb-set-tstamp-rejects-unspec-dynamic-tstamp"
        category: "helper-state"
        tags: [tc helper skb-metadata timestamp dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let tstamp = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_set_tstamp" $ctx $tstamp 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
    }
    {
        name: "tc-skb-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-skb-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let bytes = "x"'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-store-bytes-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper packet-bounds flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let bytes = "x"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_skb_store_bytes" $ctx 0 $bytes 1 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_store_bytes' requires arg4 flags"
    }
    {
        name: "tc-subfn-skb-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def mutate [skb bytes] {'
            '    helper-call "bpf_skb_store_bytes" $skb 0 $bytes 1 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  mutate $ctx $bytes'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-subfn-skb-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def mutate [skb bytes] {'
            '    helper-call "bpf_skb_store_bytes" $skb 0 $bytes 1 0'
            '    0'
            '  }'
            '  let bytes = "x"'
            '  mutate $ctx $bytes'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-subfn-skb-pull-data-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  pull $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-subfn-skb-pull-data-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper user-function packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  pull $ctx'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-nested-subfn-skb-pull-data-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper user-function nested packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def mutate [skb] {'
            '    let actual = (id $skb)'
            '    helper-call "bpf_skb_pull_data" $actual 0'
            '    0'
            '  }'
            '  let data = $ctx.data'
            '  mutate $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-record-context-helper-arg"
        category: "helper-state"
        tags: [tc helper record context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { skb: $ctx }'
            '  helper-call "bpf_skb_pull_data" $rec.skb 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-record-context-helper-arg"
        category: "helper-state"
        tags: [tc helper user-function record context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [x] { { skb: $x } }'
            '  let rec = (wrap $ctx)'
            '  helper-call "bpf_skb_pull_data" $rec.skb 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-raw-context-helper-arg"
        category: "helper-state"
        tags: [tc helper user-function context accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def pull [skb] {'
            '    helper-call "bpf_skb_pull_data" $skb 0'
            '    0'
            '  }'
            '  pull $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l3-csum-replace-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-l3-csum-replace-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l3-csum-replace-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper checksum flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_l3_csum_replace" $ctx 0 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_l3_csum_replace' requires arg4 flags"
    }
    {
        name: "tc-l4-csum-replace-rejects-stale-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "tc-l4-csum-replace-allows-reloaded-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 0'
            '  ($ctx.data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-l4-csum-replace-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper checksum flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_l4_csum_replace" $ctx 0 0 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_l4_csum_replace' requires arg4 flags"
    }
    {
        name: "tc-csum-update-preserves-packet-data"
        category: "helper-state"
        tags: [tc helper checksum packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_csum_update" $ctx 0'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-set-hash-invalid-preserves-packet-data"
        category: "helper-state"
        tags: [tc helper hash packet-bounds accept]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  helper-call "bpf_set_hash_invalid" $ctx'
            '  ($data | get 0) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-set-hash-invalid-rejects-return-use"
        category: "helper-state"
        tags: [tc helper hash void-return reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_hash_invalid" $ctx | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void helper 'bpf_set_hash_invalid' return value cannot be used"
    }
    {
        name: "tc-skb-pull-data-rejects-socket-ctx-arg"
        category: "helper-state"
        tags: [tc helper raw-context reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk { helper-call "bpf_skb_pull_data" $sk 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_pull_data' arg0 expects raw context pointer"
    }
    {
        name: "tc-fib-lookup-rejects-socket-ctx-arg"
        category: "helper-state"
        tags: [tc helper fib raw-context reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:4 --max-entries 1'
            '  let params = (0 | map-get scratch --kind array)'
            '  let sk = $ctx.sk'
            '  if $sk { if $params { helper-call "bpf_fib_lookup" $sk $params 4 0 } }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' arg0 expects raw context pointer"
    }
    {
        name: "tc-fib-lookup-helper"
        category: "helper-state"
        tags: [tc helper fib accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-fib-lookup-rejects-small-params-buffer"
        category: "helper-state"
        tags: [tc helper fib bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:8 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper fib_lookup params requires 64 bytes"
    }
    {
        name: "xdp-fib-lookup-helper"
        category: "helper-state"
        tags: [xdp helper fib accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-fib-lookup-rejects-invalid-flags"
        category: "helper-state"
        tags: [xdp helper fib flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 64 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' requires arg3 flags"
    }
    {
        name: "xdp-fib-lookup-rejects-dynamic-flags"
        category: "helper-state"
        tags: [xdp helper fib flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 $flags }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' requires arg3 flags"
    }
    {
        name: "xdp-fib-lookup-rejects-small-params-buffer"
        category: "helper-state"
        tags: [xdp helper fib bounds reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:8 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper fib_lookup params requires 64 bytes"
    }
    {
        name: "sk-skb-fib-lookup-rejects-program"
        category: "helper-state"
        tags: [sk-skb helper fib program-policy reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_fib_lookup' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "xdp-check-mtu-helper"
        category: "helper-state"
        tags: [xdp helper mtu accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-check-mtu-rejects-nonzero-flags"
        category: "helper-state"
        tags: [xdp helper mtu flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 1 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
    }
    {
        name: "xdp-check-mtu-rejects-dynamic-flags"
        category: "helper-state"
        tags: [xdp helper mtu flags reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 $flags }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
    }
    {
        name: "tc-check-mtu-helper"
        category: "helper-state"
        tags: [tc helper mtu accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 1 }'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-check-mtu-rejects-small-mtu-len"
        category: "helper-state"
        tags: [tc helper mtu bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:2 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper check_mtu mtu_len requires 4 bytes"
    }
    {
        name: "sk-skb-check-mtu-rejects-program"
        category: "helper-state"
        tags: [sk-skb helper mtu program-policy reject source metadata]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_check_mtu' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "tc-skb-get-tunnel-key-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-get-tunnel-key-rejects-invalid-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 2 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-get-tunnel-key-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_get_tunnel_key" $ctx $key 44 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-get-tunnel-opt-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_get_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tunnel-key-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tunnel-key-rejects-invalid-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 32 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-set-tunnel-key-rejects-dynamic-flags"
        category: "helper-state"
        tags: [tc helper tunnel flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_key --kind array --value-type bytes:44 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let key = (0 | map-get tunnel_key --kind array)'
            '  if $key { helper-call "bpf_skb_set_tunnel_key" $ctx $key 44 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tunnel_key' requires arg3 flags"
    }
    {
        name: "tc-skb-set-tunnel-opt-helper"
        category: "helper-state"
        tags: [tc helper tunnel accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_set_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-set-tunnel-opt-accepts-dynamic-aligned-size"
        category: "helper-state"
        tags: [tc helper tunnel size dynamic accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt_dyn_ok --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt_dyn_ok --kind array)'
            '  if $opt {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_skb_set_tunnel_opt" $ctx $opt $size'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-skb-set-tunnel-opt-rejects-small-buffer"
        category: "helper-state"
        tags: [tc helper tunnel bounds reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt --kind array --value-type bytes:8 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt --kind array)'
            '  if $opt { helper-call "bpf_skb_set_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_tunnel buffer requires 16 bytes"
    }
    {
        name: "tc-skb-set-tunnel-opt-rejects-dynamic-unaligned-size"
        category: "helper-state"
        tags: [tc helper tunnel size dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt_dyn_bad --kind array --value-type bytes:16 --max-entries 1'
            '  let opt = (0 | map-get tunnel_opt_dyn_bad --kind array)'
            '  if $opt {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 10 })'
            '    helper-call "bpf_skb_set_tunnel_opt" $ctx $opt $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_set_tunnel_opt' requires arg2 size to be a multiple of 4"
    }
    {
        name: "tc-skb-set-tunnel-opt-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [tc helper tunnel bounds dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define tunnel_opt_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let opt_a = (0 | map-get tunnel_opt_dyn_short --kind array)'
            '  let opt_b = (0 | map-get tunnel_opt_dyn_short --kind array)'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let opt = (if $selector == 0 { $opt_a } else { $opt_b })'
            '  if $opt { helper-call "bpf_skb_set_tunnel_opt" $ctx $opt 16 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_tunnel buffer requires 16 bytes"
    }
    {
        name: "tc-skb-load-bytes-relative-helper"
        category: "helper-state"
        tags: [tc helper skb-load-bytes accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define rel_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get rel_bytes --kind array)'
            '  if $dst { helper-call "bpf_skb_load_bytes_relative" $ctx 0 $dst 8 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-skb-load-bytes-relative-rejects-invalid-start"
        category: "helper-state"
        tags: [tc helper skb-load-bytes flags reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define rel_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get rel_bytes --kind array)'
            '  if $dst { helper-call "bpf_skb_load_bytes_relative" $ctx 0 $dst 8 2 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_load_bytes_relative' requires arg4 start_header"
    }
    {
        name: "tc-skb-load-bytes-relative-rejects-dynamic-start"
        category: "helper-state"
        tags: [tc helper skb-load-bytes flags dynamic reject source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define rel_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get rel_bytes --kind array)'
            '  let start = (helper-call "bpf_get_prandom_u32")'
            '  if $dst { helper-call "bpf_skb_load_bytes_relative" $ctx 0 $dst 8 $start }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_load_bytes_relative' requires arg4 start_header"
    }
    {
        name: "helper-get-stack-rejects-task-ctx-arg"
        category: "helper-state"
        tags: [helper raw-context reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get scratch --kind array)'
            '  let task = (helper-call "bpf_get_current_task_btf")'
            '  if $dst { helper-call "bpf_get_stack" $task $dst 8 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stack' arg0 expects raw context pointer"
    }
    {
        name: "source-helper-get-stack-accepts-map-buffer"
        category: "helper-state"
        tags: [helper stack-copy accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-stack-accepts-zero-size-buffer"
        category: "helper-state"
        tags: [helper stack-copy zero-size accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_zero_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_zero_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 0 2559 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-stack-rejects-small-buffer"
        category: "helper-state"
        tags: [helper stack-copy bounds reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_small_buf --kind array --value-type bytes:8 --max-entries 1'
            '  let buf = (0 | map-get get_stack_small_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 64 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_stack buf requires 64 bytes"
    }
    {
        name: "source-helper-get-stack-rejects-negative-size"
        category: "helper-state"
        tags: [helper stack-copy size reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_negative_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_negative_buf)'
            '  let size = (0 - 1)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf $size 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-get-stack-rejects-dynamic-negative-size"
        category: "helper-state"
        tags: [helper stack-copy size dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_dynamic_negative_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_dynamic_negative_buf)'
            '  let size = (0 - (helper-call "bpf_get_prandom_u32"))'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf $size 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require arg2 size to be between 0 and u32::MAX"
    }
    {
        name: "source-helper-get-stack-rejects-invalid-flags"
        category: "helper-state"
        tags: [helper stack-copy flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_flag_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_flag_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 512 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require flags"
    }
    {
        name: "source-helper-get-stack-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper stack-copy flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define get_stack_dynamic_flag_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let buf = (0 | map-get get_stack_dynamic_flag_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 $flags }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stack-copy helpers require flags"
    }
    {
        name: "source-helper-get-stack-rejects-xdp"
        category: "helper-state"
        tags: [helper stack-copy program-policy reject source metadata]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define get_stack_xdp_buf --kind array --value-type bytes:24 --max-entries 1'
            '  let buf = (0 | map-get get_stack_xdp_buf)'
            '  if $buf { helper-call "bpf_get_stack" $ctx $buf 24 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_stack' is only valid"
    }
    {
        name: "helper-packet-output-accepts-skb-argument"
        category: "helper-state"
        tags: [helper packet-output skb tracing accept source metadata]
        requires: [kernel-btf]
        target: "fentry:netif_receive_skb"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_skb_output" $ctx.arg0 packet_events 0 $data 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "helper-packet-output-rejects-raw-tracing-context"
        category: "helper-state"
        tags: [helper packet-output skb tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:netif_receive_skb"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_skb_output" $ctx packet_events 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_output' arg0 expects sk_buff pointer"
    }
    {
        name: "helper-xdp-output-rejects-raw-tracing-context"
        category: "helper-state"
        tags: [helper packet-output xdp tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:xdp_do_redirect"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_xdp_output" $ctx packet_events 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_xdp_output' arg0 expects xdp_buff pointer"
    }
    {
        name: "xdp-load-bytes-helper"
        category: "helper-state"
        tags: [xdp helper bytes accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get scratch --kind array)'
            '  if $dst { helper-call "bpf_xdp_load_bytes" $ctx 0 $dst 8 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-store-bytes-preserves-packet-data"
        category: "helper-state"
        tags: [xdp helper bytes packet-bounds accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "x"'
            '  helper-call "bpf_xdp_store_bytes" $ctx 0 $bytes 1'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-store-bytes-rejects-small-source-buffer"
        category: "helper-state"
        tags: [xdp helper bytes bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define scratch --kind array --value-type bytes:1 --max-entries 1'
            '  let bytes = (0 | map-get scratch --kind array)'
            '  if $bytes { helper-call "bpf_xdp_store_bytes" $ctx 0 $bytes 8 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper xdp_bytes buf requires 8 bytes"
    }
    {
        name: "xdp-store-bytes-rejects-dynamic-small-source-buffer"
        category: "helper-state"
        tags: [xdp helper bytes bounds dynamic reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define scratch_dyn_short --kind array --value-type bytes:1 --max-entries 1'
            '  let bytes = (0 | map-get scratch_dyn_short --kind array)'
            '  if $bytes {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 1 } else { 8 })'
            '    helper-call "bpf_xdp_store_bytes" $ctx 0 $bytes $size'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper xdp_bytes buf requires 8 bytes"
    }
    {
        name: "source-helper-xdp-adjust-and-buffer-len"
        category: "helper-state"
        tags: [xdp helper adjust-packet accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_xdp_adjust_head" $ctx 0'
            '  helper-call "bpf_xdp_adjust_meta" $ctx 0'
            '  helper-call "bpf_xdp_adjust_tail" $ctx 0'
            '  let len = (helper-call "bpf_xdp_get_buff_len" $ctx)'
            '  $len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-xdp-adjust-rejects-non-xdp-context"
        category: "helper-state"
        tags: [xdp helper adjust-packet program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_xdp_adjust_head" $ctx 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_xdp_adjust_head' is only valid in xdp programs"
    }
    {
        name: "source-helper-tc-skb-hash-csum-and-cgroup"
        category: "helper-state"
        tags: [tc helper skb cgroup accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_hash_recalc" $ctx'
            '  helper-call "bpf_csum_level" $ctx 0'
            '  helper-call "bpf_set_hash" $ctx 0'
            '  helper-call "bpf_skb_under_cgroup" $ctx tracked_cgroups 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-current-task-under-cgroup"
        category: "helper-state"
        tags: [helper current cgroup accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_current_task_under_cgroup" tracked_cgroups 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-sk-msg-byte-count"
        category: "helper-state"
        tags: [sk-msg helper bytes accept source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_msg_apply_bytes" $ctx 8'
            '  helper-call "bpf_msg_cork_bytes" $ctx 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sock-ops-cb-flags-set"
        category: "helper-state"
        tags: [sock-ops helper accept source metadata]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_sock_ops_cb_flags_set" $ctx 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-trace-printk"
        category: "helper-state"
        tags: [helper trace-printk accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_trace_printk" "hello" 5'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-send-signal"
        category: "helper-state"
        tags: [helper signal accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_send_signal" 0'
            '  helper-call "bpf_send_signal_thread" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-per-cpu-pointers"
        category: "helper-state"
        tags: [helper per-cpu accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_per_cpu_ptr" $ctx 0'
            '  helper-call "bpf_this_cpu_ptr" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-socket-conversions"
        category: "helper-state"
        tags: [tc cgroup-skb cgroup-sockopt helper socket accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    let full = (helper-call "bpf_sk_fullsock" $sk)'
            '    if $full { $full.family | count }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-tcp-sock-conversion"
        category: "helper-state"
        tags: [cgroup-sockopt helper socket accept source metadata]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    let tcp = (helper-call "bpf_tcp_sock" $sk)'
            '    if $tcp { $tcp.snd_cwnd | count }'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-listener-sock-conversion"
        category: "helper-state"
        tags: [cgroup-skb helper socket accept source metadata]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    let listener = (helper-call "bpf_get_listener_sock" $sk)'
            '    if $listener { $listener.family | count }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-sk-cgroup-ids"
        category: "helper-state"
        tags: [cgroup-skb helper socket cgroup accept source metadata]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    helper-call "bpf_sk_cgroup_id" $sk'
            '    helper-call "bpf_sk_ancestor_cgroup_id" $sk 0'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-task-and-file-pointer-helpers"
        category: "helper-state"
        tags: [fentry helper task file socket accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_pt_regs" $ctx.task'
            '  helper-call "bpf_sock_from_file" $ctx.arg.file'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-helper-skc-socket-conversions"
        category: "helper-state"
        tags: [sk-lookup helper socket accept source metadata]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    helper-call "bpf_skc_to_tcp_sock" $sk'
            '    helper-call "bpf_skc_to_tcp6_sock" $sk'
            '    helper-call "bpf_skc_to_tcp_timewait_sock" $sk'
            '    helper-call "bpf_skc_to_tcp_request_sock" $sk'
            '    helper-call "bpf_skc_to_udp6_sock" $sk'
            '    helper-call "bpf_skc_to_mptcp_sock" $sk'
            '    helper-call "bpf_skc_to_unix_sock" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-non-tc"
        category: "helper-state"
        tags: [helper xfrm reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' is only valid in tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-nonzero-flags"
        category: "helper-state"
        tags: [tc helper xfrm flags reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let state = "0123456789abcdef"'
            '  helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-small-buffer"
        category: "helper-state"
        tags: [tc helper xfrm bounds reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define xfrm_states --kind array --value-type "bytes:8" --max-entries 1'
            '  let state = (0 | map-get xfrm_states --kind array)'
            '  if $state { helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state 16 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_get_xfrm_state xfrm_state requires 16 bytes"
    }
    {
        name: "tc-skb-get-xfrm-state-helper-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [tc helper xfrm bounds dynamic reject]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define xfrm_states_dyn_short --kind array --value-type "bytes:8" --max-entries 1'
            '  let state = (0 | map-get xfrm_states_dyn_short --kind array)'
            '  if $state {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_skb_get_xfrm_state" $ctx 0 $state $size 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper skb_get_xfrm_state xfrm_state requires 16 bytes"
    }
    {
        name: "tc-egress-helper-backed-context"
        category: "context-surface"
        tags: [tc context helper-backed egress]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tc context reject egress-only]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-ingress-skb-context-write"
        category: "context-surface"
        tags: [tcx context packet writable]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-ingress-context-socket-write"
        category: "context-surface"
        tags: [tcx context writable socket]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-egress-helper-backed-context"
        category: "context-surface"
        tags: [tcx context helper-backed egress]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tcx-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tcx context reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "next"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-egress-rejects-context-socket-write"
        category: "context-policy"
        tags: [tcx context writable socket reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs"
    }
    {
        name: "netkit-primary-skb-context-write"
        category: "context-surface"
        tags: [netkit context packet writable]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.3 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-rejects-context-socket-write"
        category: "context-policy"
        tags: [netkit context writable socket reject]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs"
    }
    {
        name: "netkit-peer-skb-context"
        category: "context-surface"
        tags: [netkit context packet]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.ingress_ifindex + $ctx.queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "netkit-rejects-egress-context"
        category: "context-policy"
        tags: [netkit context reject egress-only]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc_action, tc:egress, and tcx:egress programs"
    }
    {
        name: "xdp-rejects-pid-context"
        category: "context-policy"
        tags: [xdp reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on xdp programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-interface"
        category: "context-policy"
        tags: [xdp reject devmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-cpumap"
        category: "context-policy"
        tags: [xdp reject cpumap devmap]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "socket-filter-rejects-direct-data"
        category: "context-policy"
        tags: [socket-filter reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data is not available on socket_filter programs"
    }
    {
        name: "socket-filter-tcp6-context"
        category: "context-surface"
        tags: [socket-filter context ipv6]
        target: "socket_filter:tcp6:[::1]:8080"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rich-skb-context"
        category: "context-surface"
        tags: [socket-filter context packet source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.pkt_type + $ctx.queue_mapping + $ctx.protocol + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.tc_index + $ctx.hash + $ctx.mark + $ctx.priority) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.0) | count'
            '  "keep"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-cb-context-write"
        category: "context-surface"
        tags: [socket-filter context writable]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.1 = 7'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "socket-filter-rejects-mark-context-write"
        category: "context-policy"
        tags: [socket-filter context writable reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is read-only"
    }
    {
        name: "cgroup-skb-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.remote_ip4 + $ctx.local_port + $ctx.sk.cgroup_id + $ctx.sk.ancestor_cgroup_id.0) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-rich-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context egress source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.napi_id + $ctx.gso_segs + $ctx.gso_size + $ctx.ingress_ifindex + $ctx.ifindex + $ctx.tc_index + $ctx.hash + $ctx.tstamp + $ctx.hwtstamp) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 1) + $ctx.family + $ctx.socket_cookie + $ctx.socket_uid + $ctx.netns_cookie) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-egress-timestamp-context-write"
        category: "context-surface"
        tags: [cgroup-skb context writable timestamp egress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.tstamp + $ctx.hwtstamp + $ctx.priority) | count'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-ingress-rejects-tstamp-write"
        category: "context-policy"
        tags: [cgroup-skb context reject writable ingress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    }
    {
        name: "cgroup-skb-ingress-writable-context"
        category: "context-surface"
        tags: [cgroup-skb context writable]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-create-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.sock_type + $ctx.protocol + $ctx.state + $ctx.rx_queue_mapping + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-release-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_release"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-post-bind6-context"
        category: "context-surface"
        tags: [cgroup-sock context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-socket-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sock context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-rejects-post-bind-mark-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-post-bind-bound-dev-if-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.bound_dev_if = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.bound_dev_if is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-post-bind-priority-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.priority is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-create-local-ip4"
        category: "context-policy"
        tags: [cgroup-sock reject]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  $ctx.local_ip4 | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_ip4 is only available on cgroup_sock post_bind4"
    }
    {
        name: "cgroup-sock-rejects-post-bind4-src-ip6"
        category: "context-policy"
        tags: [cgroup-sock reject ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sk.src_ip6 | get 0) | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk.src_ip6 is only available on cgroup_sock post_bind6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-port"
        category: "context-policy"
        tags: [cgroup-sock-addr reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  $ctx.local_port | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_port is only available on cgroup_sock_addr bind4/bind6 and getsockname4/getsockname6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-ip4-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6"
    }
    {
        name: "cgroup-sock-addr-rejects-connect6-user-ip4-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable ipv4]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_ip4 is only available on IPv4 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-user-ip6-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_ip6.0 = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_ip6 is only available on IPv6 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-unix-remote-port-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable unix]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.remote_port is only available on IPv4/IPv6 cgroup_sock_addr hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-user-family-write"
        category: "context-policy"
        tags: [cgroup-sock-addr reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.user_family = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.user_family is read-only"
    }
    {
        name: "cgroup-sock-addr-connect4-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-socket-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect4-alias-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.remote_ip4 = 2130706433'
            '  $event.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-connect6-indexed-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  (($ctx.user_ip6 | get 3) + ($ctx.remote_ip6 | get 3) + $ctx.user_port + $ctx.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getpeername4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getsockname6-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-getsockname6-alias-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-sendmsg6-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable ipv6 source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-alias-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-user-function-returned-context-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut event = (get_event $ctx)'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-record-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-record-upsert-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record upsert source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-record-spread-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-user-function-record-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc record user-function source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-accepts-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $ctx $path 17'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-accepts-copied-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept context-alias]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $raw_ctx $path 17'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-user-function-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def set_path [raw_ctx] {'
            '    let path = "/tmp/nu-ebpf.sock"'
            '    kfunc-call "bpf_sock_addr_set_sun_path" $raw_ctx $path 17'
            '    0'
            '  }'
            '  set_path $ctx'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-returned-raw-context"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source accept user-function metadata]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $raw_ctx $path 17'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sock-addr-set-sun-path-rejects-socket-arg"
        category: "kfunc"
        tags: [cgroup-sock-addr kfunc unix source reject]
        requires: [cgroup-v2 kernel-btf]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let path = "/tmp/nu-ebpf.sock"'
            '  kfunc-call "bpf_sock_addr_set_sun_path" $ctx.sk $path 17'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_addr_set_sun_path' arg0 expects bpf_sock_addr pointer"
    }
    {
        name: "source-helper-bind-cgroup-sock-addr-connect4"
        category: "helper-state"
        tags: [helper-call cgroup-sock-addr socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  let addr = "0123456789abcdef"'
            '  helper-call "bpf_bind" $ctx $addr 16'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-bind-rejects-non-connect-hook"
        category: "helper-state"
        tags: [helper-call cgroup-sock-addr socket-option source reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  let addr = "0123456789abcdef"'
            '  helper-call "bpf_bind" $ctx $addr 16'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bind' is only valid on cgroup_sock_addr connect4/connect6 hooks"
    }
    {
        name: "flow-dissector-flow-key-context"
        category: "context-surface"
        tags: [flow-dissector context]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.flow_keys.ip_proto + $ctx.flow_keys.nhoff + $ctx.flow_keys.thoff + ($ctx.flow_keys.ipv6_dst | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-flow-key-context"
        category: "context-surface"
        tags: [flow-dissector context alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let keys = $ctx.flow_keys'
            '  ($keys.addr_proto + $keys.is_frag + $keys.is_first_frag + $keys.is_encap + $keys.n_proto + $keys.sport + $keys.dport + $keys.ipv4_src + $keys.ipv4_dst + $keys.flags + $keys.flow_label) | count'
            '  (($keys.ipv6_src | get 0) + ($keys.ipv6_dst | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-alias-context"
        category: "context-surface"
        tags: [flow-dissector context alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let keys = $ctx.flow_keys'
            '  ($keys.protocol + $keys.transport_header_offset + $keys.src_port + $keys.destination_ip4 + ($keys.dst_ip6 | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  $ctx.flow_keys.nhoff = 14'
            '  $ctx.flow_keys.ipv6_dst.3 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-flow-key-alias-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.protocol = 6'
            '  $keys.network_header_offset = 14'
            '  $keys.dst_ip6.3 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-bound-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable alias get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-returned-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function alias source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event.flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-returned-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function alias get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 17'
            '  $keys.ipv6_src.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-upsert-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline upsert get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-insert-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline insert get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-merge-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline merge get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-default-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline default get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-update-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline update get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: null } | update keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-pipeline-select-reject-rename-get-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record pipeline select reject rename get source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: ($ctx | get flow_keys), keep: 1 } | select keys keep | reject keep | rename parsed)'
            '  $rec.parsed.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-record-spread-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable record spread source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let base = { keys: $ctx.flow_keys }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-user-function-record-flow-key-write-context"
        category: "context-surface"
        tags: [flow-dissector context writable user-function record source metadata]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def wrap [keys] { { keys: $keys } }'
            '  let keys = $ctx.flow_keys'
            '  mut rec = (wrap $keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-rejects-flow-key-root-write"
        category: "context-surface"
        tags: [flow-dissector reject context writable]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a scalar field, not the root context pointer"
    }
    {
        name: "flow-dissector-rejects-flow-key-aggregate-write"
        category: "context-surface"
        tags: [flow-dissector reject context writable]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ipv6_dst = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a scalar field, not Array"
    }
    {
        name: "flow-dissector-packet-context"
        category: "context-surface"
        tags: [flow-dissector context packet]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "flow-dissector-rejects-packet-data-write"
        category: "context-policy"
        tags: [flow-dissector reject context packet writable]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.data.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on flow_dissector programs"
    }
    {
        name: "flow-dissector-rejects-bound-packet-data-write"
        category: "context-policy"
        tags: [flow-dissector reject context packet writable alias]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 1'
            '  "parsed"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "direct packet writes are not supported on flow_dissector programs"
    }
    {
        name: "flow-dissector-rejects-skb-packet-len-context"
        category: "context-policy"
        tags: [flow-dissector reject context]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len is not available on flow_dissector programs"
    }
    {
        name: "flow-dissector-rejects-socket-context"
        category: "context-policy"
        tags: [flow-dissector reject context socket]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    }
    {
        name: "flow-dissector-rejects-flow-keys-helper-buffer"
        category: "context-policy"
        tags: [flow-dissector reject helper-call]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_load_bytes" $ctx 0 $ctx.flow_keys 4'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects pointer in [Stack, Map], got Context"
    }
    {
        name: "flow-dissector-rejects-flow-keys-kernel-helper-arg"
        category: "context-policy"
        tags: [flow-dissector reject helper-call]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  map-define kptr_slots --kind hash --value-type "record{task:kptr:task_struct}"'
            '  let entry = (0 | map-get kptr_slots --kind hash)'
            '  if $entry { helper-call "bpf_kptr_xchg" $entry.task $ctx.flow_keys | count }'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper kptr_xchg ptr expects pointer in [Kernel], got Context"
    }
    {
        name: "netfilter-state-context"
        category: "context-surface"
        tags: [netfilter context]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.hook + $ctx.pf + $ctx.protocol_family + $ctx.state.in.ifindex + $ctx.nf_state.out.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-bound-state-context"
        category: "context-surface"
        tags: [netfilter context alias]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let state = ($ctx.nf_state)'
            '  let skb = $ctx.skb'
            '  ($state.in.ifindex + $skb.len) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-bound-state-hop-context"
        category: "context-surface"
        tags: [netfilter context alias]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let input = $ctx.state.in'
            '  ($input.ifindex + $ctx.hook) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-record-state-context"
        category: "context-surface"
        tags: [netfilter context record source metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let rec = { state: $ctx.nf_state skb: $ctx.skb }'
            '  ($rec.state.in.ifindex + $rec.skb.len + $ctx.hook) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-record-spread-state-context"
        category: "context-surface"
        tags: [netfilter context record spread source metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let base = { state: $ctx.state }'
            '  let rec = { ok: true, ...$base, skb: $ctx.skb }'
            '  ($rec.state.out.ifindex + $rec.skb.len + $ctx.pf) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-user-function-record-state-context"
        category: "context-surface"
        tags: [netfilter context user-function record source metadata]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  def wrap [state] { { state: $state } }'
            '  let rec = (wrap $ctx.nf_state)'
            '  ($rec.state.in.ifindex + $ctx.skb.len + $ctx.protocol_family) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-rejects-flow-keys-context"
        category: "context-policy"
        tags: [netfilter reject context]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys.ip_proto | count'
            '  "accept"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.flow_keys is only available on flow_dissector programs"
    }
    {
        name: "netfilter-rejects-packet-context"
        category: "context-policy"
        tags: [netfilter reject context packet]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "accept"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len is only available on packet-context programs"
    }
    {
        name: "cgroup-sockopt-retval-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-retval-alias-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-set-scalar-writes"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  $ctx.optname = 2'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-set-scalar-alias-writes"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.level = 1'
            '  $event.optname = 2'
            '  $event.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-alias-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut event = $ctx'
            '  $event.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-bound-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-bound-get-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable alias get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = ($ctx | get optval)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-returned-context-root-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event.optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-returned-get-context-root-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function alias get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event | get optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: $ctx.optval }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-get-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: ($ctx | get optval) }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-pipeline-upsert-get-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record pipeline upsert get source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert optval ($ctx | get optval))'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-record-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-record-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-user-function-record-direct-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record spread source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] {'
            '    let base = { optval: $optval }'
            '    { ok: true, ...$base }'
            '  }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-optval-nested-user-function-record-spread-byte-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable user-function record spread nested source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  def outer [event] {'
            '    let optval = $event.optval'
            '    let base = (wrap $optval)'
            '    { ok: true, ...$base }'
            '  }'
            '  mut rec = (outer $ctx)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-setsockopt-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_setsockopt" $ctx 1 2 $optval 8'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-getsockopt-rejects-non-socket-option-context"
        category: "helper-state"
        tags: [helper-call cgroup-sockopt socket-option source reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let optval = "01234567"'
            '  helper-call "bpf_getsockopt" $ctx 1 2 $optval 8'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_getsockopt' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs"
    }
    {
        name: "source-helper-get-retval-cgroup-device"
        category: "helper-state"
        tags: [helper-call cgroup-retval source accept]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-set-retval-cgroup-sock"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-cgroup-sockopt"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sockopt source accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-set-retval-cgroup-sock-addr-sendmsg"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock-addr source accept]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-cgroup-sysctl"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sysctl source accept]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-retval-rejects-non-cgroup-context"
        category: "helper-state"
        tags: [helper-call cgroup-retval source reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_retval" | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs"
    }
    {
        name: "source-helper-set-retval-rejects-cgroup-sock-addr-getpeername"
        category: "helper-state"
        tags: [helper-call cgroup-retval cgroup-sock-addr source reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_set_retval" (-1)'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_set_retval' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks"
    }
    {
        name: "cgroup-sockopt-get-context-fields"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  ($ctx.level + $ctx.optname + $ctx.optlen + $ctx.retval + $ctx.netns_cookie) | count'
            '  if $ctx.optval { 1 | count }'
            '  if $ctx.optval_end { 1 | count }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-optlen-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-get-rejects-level-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.level is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-get-rejects-optname-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optname = 2'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optname is only writable on cgroup_sockopt:set hooks"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-without-index"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval = 42'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-write"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-set-rejects-retval-read"
        category: "context-policy"
        tags: [cgroup-sockopt reject context]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cgroup_sockopt:get"
    }
    {
        name: "cgroup-sockopt-rejects-optval-write-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sockopt reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.0 = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.optval is only available on cgroup_sockopt programs"
    }
    {
        name: "cgroup-sockopt-bound-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-bound-parenthesized-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-sockopt context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp {'
            '    $tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-bound-tcp-helper-pointer"
        category: "context-surface"
        tags: [cgroup-sockopt context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp {'
            '    $tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sockopt-record-bound-tcp-helper-pointer"
        category: "context-surface"
        tags: [cgroup-sockopt context record alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp {'
            '    $rec.tcp.snd_cwnd | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-bound-full-helper-pointer"
        category: "context-surface"
        tags: [tc context alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-user-function-returned-context-root-projection"
        category: "context-surface"
        tags: [tc context user-function alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [event] { $event.sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-context-root-projection"
        category: "context-surface"
        tags: [tc context record source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-record-bound-context-root-projection"
        category: "context-surface"
        tags: [tc context record alias source metadata]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { socket: $sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-bound-listener-helper-pointer"
        category: "context-surface"
        tags: [cgroup-skb context alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-skb-socket-helper-root-alias-context"
        category: "context-surface"
        tags: [cgroup-skb context socket alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sock.listener'
            '  let full = $ctx.socket.full'
            '  if $listener {'
            '    $listener.family | count'
            '  }'
            '  if $full {'
            '    $full.family | count'
            '  }'
            '  ($ctx.sock.cgroup_id + $ctx.socket.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-context"
        category: "context-surface"
        tags: [cgroup-device context]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-current-context"
        category: "context-surface"
        tags: [cgroup-device context current]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-device-rejects-packet-context"
        category: "context-policy"
        tags: [cgroup-device reject context]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.access_type | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.access_type is only available on cgroup_device programs"
    }
    {
        name: "cgroup-device-rejects-major-write"
        category: "context-policy"
        tags: [cgroup-device reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.major = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.major is read-only"
    }
    {
        name: "cgroup-sysctl-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = 0'
            '  $ctx.new_value = "1"'
            '  $ctx.name | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-record-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable record source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-base-name-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.write + $ctx.file_pos) | count'
            '  $ctx.base_name | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-user-function-returned-context-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut writable = (get_event $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-current-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.current_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-read"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgroup-sysctl-rejects-write-field-write"
        category: "context-policy"
        tags: [cgroup-sysctl reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.write = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.write is read-only"
    }
    {
        name: "cgroup-sysctl-rejects-new-value-index-write"
        category: "context-policy"
        tags: [cgroup-sysctl reject context writable]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.new_value.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.new_value does not support indexed assignment"
    }
    {
        name: "cgroup-sysctl-rejects-file-pos-on-packet-context"
        category: "context-policy"
        tags: [cgroup-sysctl reject context]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.file_pos | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.file_pos is only available on cgroup_sysctl programs"
    }
    {
        name: "sock-ops-basic-context-write"
        category: "context-surface"
        tags: [sock-ops context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.reply + ($ctx.replylong | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.reply = 1'
            '  $ctx.replylong.0 = 7'
            '  $ctx.cb_flags = 1'
            '  $ctx.sk_txhash = 7'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-record-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable record source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-cb-flags-user-function-returned-context-write"
        category: "context-surface"
        tags: [sock-ops context writable user-function alias source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_event [event] { $event }'
            '  mut writable = (get_event $ctx)'
            '  $writable.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-metrics-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.is_fullsock + $ctx.snd_cwnd + $ctx.srtt_us + $ctx.state + $ctx.rtt_min + $ctx.snd_ssthresh + $ctx.rcv_nxt + $ctx.snd_nxt) | count'
            '  ($ctx.snd_una + $ctx.mss_cache + $ctx.ecn_flags + $ctx.rate_delivered + $ctx.rate_interval_us + $ctx.packets_out + $ctx.retrans_out + $ctx.total_retrans) | count'
            '  ($ctx.segs_in + $ctx.data_segs_in + $ctx.segs_out + $ctx.data_segs_out + $ctx.lost_out + $ctx.sacked_out + ($ctx.bytes_received mod 1024) + ($ctx.bytes_acked mod 1024)) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-rejects-replylong-write-without-index"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.replylong = 7'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a fixed index"
    }
    {
        name: "sock-ops-rejects-reply-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.reply = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-rejects-cb-flags-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-rejects-sk-txhash-write-on-packet-context"
        category: "context-policy"
        tags: [sock-ops reject context writable]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk_txhash = 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "sock_ops programs"
    }
    {
        name: "sock-ops-bound-socket-projection-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-bound-socket-parenthesized-projection-context"
        category: "context-surface"
        tags: [sock-ops context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-socket-root-alias-context"
        category: "context-surface"
        tags: [sock-ops context socket alias source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sock = $ctx.sock'
            '  ($sock.rx_queue_mapping + $ctx.socket.state) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-enable-tx-tstamp-kfunc"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-copied-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata context-alias]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-user-function-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def enable [raw_ctx] {'
            '    kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '    0'
            '  }'
            '  enable $ctx'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-returned-raw-context"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata user-function]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $raw_ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-rejects-socket-arg"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source reject]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx.sk 0'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_ops_enable_tx_tstamp' arg0 expects bpf_sock_ops pointer"
    }
    {
        name: "sock-ops-enable-tx-tstamp-rejects-non-sock-ops"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  2'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_sock_ops_enable_tx_tstamp' is only valid in sock_ops programs"
    }
    {
        name: "sock-ops-hdr-opt-helpers"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  helper-call "bpf_load_hdr_opt" $ctx $opt 16 0'
            '  helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '  helper-call "bpf_reserve_hdr_opt" $ctx 16 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-load-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_load_hdr_opt" $ctx $opt 16 $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_load_hdr_opt' requires arg3 flags"
    }
    {
        name: "sock-ops-store-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let opt = "0123456789abcdef"'
            '    let flags = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 $flags'
            '  }'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_store_hdr_opt' requires arg3 = 0"
    }
    {
        name: "sock-ops-reserve-hdr-opt-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_reserve_hdr_opt" $ctx 16 $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_reserve_hdr_opt' requires arg2 = 0"
    }
    {
        name: "sock-ops-sock-map-update-helper"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap accept source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-sock-hash-update-helper"
        category: "helper-state"
        tags: [sock-ops helper-call sockhash accept source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_hash_update" $ctx hash_peers $key 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-sock-map-update-rejects-invalid-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 4'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-map-update-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sock_map_update" $ctx peers $key $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-hash-update-rejects-dynamic-flags"
        category: "helper-state"
        tags: [sock-ops helper-call sockhash flags reject source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_sock_hash_update" $ctx hash_peers $key $flags'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "socket map update helpers require arg3 flags"
    }
    {
        name: "sock-ops-sock-map-update-rejects-non-sock-ops"
        category: "helper-state"
        tags: [sock-ops helper-call sockmap program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  helper-call "bpf_sock_map_update" $ctx peers $key 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sock_map_update' is only valid in sock_ops programs"
    }
    {
        name: "sock-ops-store-hdr-opt-rejects-stale-data"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt packet-bounds reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let data = $ctx.data'
            '    let opt = "0123456789abcdef"'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '    ($data | get 0) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "sock-ops-store-hdr-opt-allows-reloaded-data"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt packet-bounds accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 15) {'
            '    let opt = "0123456789abcdef"'
            '    helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '    ($ctx.data | get 0) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-packet-metadata-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-metadata-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  }'
            '  if ($ctx.op == 16) {'
            '    ($ctx.packet_len + $ctx.skb_len + ($ctx.skb_hwtstamp mod 1024)) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sock-ops-packet-data-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-data-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    if ($ctx.data_end != 0) {'
            '      ($ctx.data | get 0) | count'
            '    }'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.hash + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-packet-context"
        category: "context-surface"
        tags: [sk-reuseport context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-rich-context"
        category: "context-surface"
        tags: [sk-reuseport context packet socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.type + $ctx.sk.protocol + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-socket-root-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let rec = { sock: $ctx.sk }'
            '  ($rec.sock.family + $ctx.hash) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-spread-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record spread source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  let base = { sock: $ctx.sock }'
            '  let rec = { ok: true, ...$base }'
            '  ($rec.sock.priority + $ctx.protocol) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-user-function-record-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket user-function record source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { sock: $sock } }'
            '  let rec = (wrap $ctx.sk)'
            '  ($rec.sock.rx_queue_mapping + $ctx.bind_inany) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrate-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie + $ctx.sk.bound_dev_if + $ctx.migrating_sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-migrating-socket-alias-context"
        category: "context-surface"
        tags: [sk-reuseport context socket alias source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let migrating = $ctx.migrating_socket'
            '  if $migrating {'
            '    $migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-record-migrating-socket-context"
        category: "context-surface"
        tags: [sk-reuseport context socket record source metadata]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  let rec = { migrating: $ctx.migrating_socket }'
            '  if $rec.migrating {'
            '    $rec.migrating.remote_port | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-reuseport-select-migrating-sk-nullable-context"
        category: "context-surface"
        tags: [sk-reuseport context socket source metadata]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  if $ctx.migrating_sk {'
            '    $ctx.migrating_sk.family | count'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
