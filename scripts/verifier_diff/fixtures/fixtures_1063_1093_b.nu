const VERIFIER_DIFF_FIXTURES_1063_1093_B = [
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
