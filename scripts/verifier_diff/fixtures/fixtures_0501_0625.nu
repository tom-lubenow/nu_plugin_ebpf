const VERIFIER_DIFF_FIXTURES_0501_0625 = [
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
]
