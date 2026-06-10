const VERIFIER_DIFF_FIXTURES_1063_1093 = [
    {
        name: "lwt-xmit-rejects-tc-classid-context"
        category: "context-policy"
        tags: [lwt reject context]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.tc_classid | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "lwt-xmit-rejects-socket-context"
        category: "context-policy"
        tags: [lwt reject context socket]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    }
    {
        name: "lwt-push-encap-rejects-non-lwt-program"
        category: "helper-policy"
        tags: [lwt helper-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs"
    }
    {
        name: "lwt-xmit-push-encap-helper"
        category: "helper-state"
        tags: [lwt helper-call accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  map-define encap_hdr --kind array --value-type bytes:16 --max-entries 1'
            '  let hdr = (0 | map-get encap_hdr --kind array)'
            '  if $hdr { helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16 }'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-push-encap-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds reject source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16'
            '  ($data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-xmit-push-encap-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call packet-bounds accept source metadata]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  let hdr = "0123456789abcdef"'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 $hdr 16'
            '  ($ctx.data | get 0) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:16 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-stale-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "lwt-seg6local-store-bytes-allows-reloaded-data"
        category: "helper-state"
        tags: [lwt helper-call seg6local packet-bounds accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  let bytes = "0123456789abcdef"'
            '  helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-adjust-srh-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_seg6_adjust_srh" $ctx 0 4'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-action-helper"
        category: "helper-state"
        tags: [lwt helper-call seg6local accept source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_action --kind array --value-type bytes:16 --max-entries 1'
            '  let param = (0 | map-get seg6_action --kind array)'
            '  if $param { helper-call "bpf_lwt_seg6_action" $ctx 0 $param 16 }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes --kind array)'
            '  if $bytes { helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes 16 }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lwt-seg6local-store-bytes-rejects-dynamic-small-buffer"
        category: "helper-state"
        tags: [lwt helper-call seg6local bounds dynamic reject source metadata]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  map-define seg6_bytes_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let bytes = (0 | map-get seg6_bytes_dyn_short --kind array)'
            '  if $bytes {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_lwt_seg6_store_bytes" $ctx 0 $bytes $size'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper lwt buffer requires 16 bytes"
    }
    {
        name: "lirc-mode2-context"
        category: "context-surface"
        tags: [lirc context]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.sample + $ctx.value + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-current-context"
        category: "context-surface"
        tags: [lirc context current]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lirc-mode2-rc-helpers"
        category: "helper-state"
        tags: [lirc helper-call accept source metadata]
        target: "lirc_mode2:/dev/null"
        program: [
            '{|ctx|'
            '  helper-call "bpf_rc_repeat" $ctx'
            '  helper-call "bpf_rc_keydown" $ctx 0 0 0'
            '  helper-call "bpf_rc_pointer_rel" $ctx 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tracepoint-writable-args"
        category: "context-surface"
        tags: [raw-tracepoint-w context]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-writable-current-context"
        category: "context-surface"
        tags: [raw-tracepoint-w context current]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.meta { 1 | count }'
            '  if $ctx.task { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.task { $ctx.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-meta-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  $ctx.meta.seq_num | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-alias-btf-fields"
        category: "context-surface"
        tags: [iter context alias btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-record-btf-fields"
        category: "context-surface"
        tags: [iter context record btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let rec = { meta: $ctx.iter_meta task: $ctx.iter_task }'
            '  $rec.meta.seq_num | count'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-record-spread-btf-fields"
        category: "context-surface"
        tags: [iter context record spread btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let base = { task: $ctx.iter_task }'
            '  let rec = { meta: $ctx.iter_meta, ...$base }'
            '  $rec.meta.seq_num | count'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-user-function-record-btf-fields"
        category: "context-surface"
        tags: [iter context user-function record btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  def wrap [task] { { task: $task } }'
            '  let rec = (wrap $ctx.iter_task)'
            '  if $rec.task { $rec.task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-user-function-returned-btf-root-fields"
        category: "context-surface"
        tags: [iter context user-function alias btf kernel-btf source metadata]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event.iter_meta }'
            '  def get_task [event] { $event.iter_task }'
            '  let meta = (get_meta $ctx)'
            '  let task = (get_task $ctx)'
            '  $meta.seq_num | count'
            '  if $task { $task.pid | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-file-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.file { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-file-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-vma-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.vma { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-task-vma-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.vma { $ctx.vma.vm_start | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-cgroup-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
