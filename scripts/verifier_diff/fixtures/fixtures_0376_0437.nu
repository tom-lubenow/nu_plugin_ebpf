const VERIFIER_DIFF_FIXTURES_0376_0437 = [
    {
        name: "raw-ima-hash-helpers"
        category: "helper-state"
        tags: [helper ima hash accept source metadata]
        requires: [kernel-btf]
        target: "lsm.s:file_open"
        program: [
            '{|ctx|'
            '  let file_hash = "0123456789012345"'
            '  let inode_hash = "0123456789012345"'
            '  helper-call "bpf_ima_file_hash" $ctx.arg.file $file_hash 16'
            '  helper-call "bpf_ima_inode_hash" $ctx.arg.file.f_inode $inode_hash 16'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-cgrp-storage-get-helper"
        category: "maps"
        tags: [maps local-storage cgrp-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_cgrp_storage_get" cgrp_state $ctx.current_cgroup 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage sk-storage helper-call accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    helper-call "bpf_sk_storage_delete" sock_state $sk'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage task-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_delete" task_state $ctx.task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-inode-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage inode-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_inode_storage_delete" inode_state $ctx.arg.file.f_inode'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-cgrp-storage-delete-helper"
        category: "maps"
        tags: [maps local-storage cgrp-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_cgrp_storage_delete" cgrp_state $ctx.current_cgroup'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-get-rejects-cgroup-owner"
        category: "maps"
        tags: [maps local-storage task-storage helper-call reject source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.current_cgroup 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_task_storage_get' arg1 expects task pointer"
    }
    {
        name: "raw-task-storage-get-rejects-invalid-flags"
        category: "maps"
        tags: [maps local-storage task-storage helper-call flags reject source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "storage get helpers require arg3 flags"
    }
    {
        name: "raw-task-storage-get-rejects-dynamic-flags"
        category: "maps"
        tags: [maps local-storage task-storage helper-call flags dynamic reject source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "storage get helpers require arg3 flags"
    }
    {
        name: "raw-get-local-storage-rejects-deprecated-map"
        category: "maps"
        tags: [maps local-storage deprecated helper-call reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_local_storage" legacy_storage 0'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "deprecated-cgroup-storage; use cgrp-storage local-storage maps instead"
    }
    {
        name: "raw-get-local-storage-rejects-nonzero-flags"
        category: "maps"
        tags: [maps local-storage deprecated helper-call flags reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_local_storage" legacy_storage 1'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_local_storage' requires arg1 flags to be 0"
    }
    {
        name: "raw-get-local-storage-rejects-dynamic-flags"
        category: "maps"
        tags: [maps local-storage deprecated helper-call flags reject source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_get_local_storage" legacy_storage $flags'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_local_storage' requires arg1 flags to be 0"
    }
    {
        name: "task-storage-rejects-socket-owner"
        category: "maps"
        tags: [maps local-storage task-storage map-get source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_task_storage_get' arg1 expects task pointer"
    }
    {
        name: "sk-storage-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage sk-storage map-get source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get sock_state --kind sk-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_storage_get' arg1 expects socket pointer"
    }
    {
        name: "inode-storage-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage inode-storage map-get source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file | map-get inode_state --kind inode-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_inode_storage_get' arg1 expects inode pointer"
    }
    {
        name: "cgrp-storage-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-get source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_cgrp_storage_get' arg1 expects cgroup pointer"
    }
    {
        name: "task-storage-delete-rejects-cgroup-owner"
        category: "maps"
        tags: [maps local-storage task-storage map-delete source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_task_storage_delete' arg1 expects task pointer"
    }
    {
        name: "sk-storage-delete-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage sk-storage map-delete source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete sock_state --kind sk-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_storage_delete' arg1 expects socket pointer"
    }
    {
        name: "inode-storage-delete-rejects-file-owner"
        category: "maps"
        tags: [maps local-storage inode-storage map-delete source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_inode_storage_delete' arg1 expects inode pointer"
    }
    {
        name: "cgrp-storage-delete-rejects-task-owner"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-delete source reject]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_cgrp_storage_delete' arg1 expects cgroup pointer"
    }
    {
        name: "typed-map-to-map-copy"
        category: "maps"
        tags: [maps records map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-put src_records 0 --kind hash'
            '  let entry = (0 | map-get src_records --kind hash)'
            '  if $entry {'
            '    $entry | map-put dst_records 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-array-record-initializer"
        category: "maps"
        tags: [maps records arrays map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | map-put entries_by_pid 0 --kind hash'
            '  let entries = (0 | map-get entries_by_pid --kind hash)'
            '  if $entries {'
            '    (($entries | get 1).cpu) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-array-record-spread-initializer"
        category: "maps"
        tags: [maps records arrays list-spread map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  [{ pid: 7 cpu: 2 }, ...$tail] | map-put entries_by_pid 0 --kind hash'
            '  let entries = (0 | map-get entries_by_pid --kind hash)'
            '  if $entries {'
            '    (($entries | get 1).cpu) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-push-array-record-initializer"
        category: "maps"
        tags: [maps records arrays queue map-push map-pop accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  [{ pid: 7 cpu: 2 } { pid: 9 cpu: 3 }] | map-push entry_batches --kind queue'
            '  let entries = (map-pop entry_batches --kind queue)'
            '  if $entries {'
            '    (($entries | get 1).cpu) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-push-array-record-spread-initializer"
        category: "maps"
        tags: [maps records arrays queue list-spread map-push map-pop accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let tail = [{ pid: 9 cpu: 3 }]'
            '  [{ pid: 7 cpu: 2 }, ...$tail] | map-push entry_batches --kind queue'
            '  let entries = (map-pop entry_batches --kind queue)'
            '  if $entries {'
            '    (($entries | get 1).cpu) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-query-built-in-events"
        category: "maps"
        tags: [helper-call ringbuf reserved-name]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" events 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-reserve-submit-balanced"
        category: "helper-state"
        tags: [ringbuf ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-output-rejects-dynamic-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_output" events $data 4 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_output' requires arg3 flags"
    }
    {
        name: "ringbuf-reserve-user-function-submit-balanced"
        category: "helper-state"
        tags: [ringbuf ref-lifetime user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def submit [rec] {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '    0'
            '  }'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    submit $rec'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-user-function-reserve-submit-balanced"
        category: "helper-state"
        tags: [ringbuf ref-lifetime user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def reserve [] {'
            '    helper-call "bpf_ringbuf_reserve" events 8 0'
            '  }'
            '  let rec = (reserve)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-reserve-discard-balanced"
        category: "helper-state"
        tags: [ringbuf ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_discard" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-submit-rejects-return-use"
        category: "helper-state"
        tags: [ringbuf ref-lifetime void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0 | count'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void helper 'bpf_ringbuf_submit' return value cannot be used"
    }
    {
        name: "ringbuf-reserve-rejects-leak"
        category: "helper-state"
        tags: [ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased ringbuf record reference"
    }
    {
        name: "ringbuf-submit-rejects-partial-reserve-submit"
        category: "helper-state"
        tags: [ringbuf ref-lifetime phi accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let rec = (if $selector == 0 { helper-call "bpf_ringbuf_reserve" events 8 0 } else { 0 })'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-reserve-rejects-nonzero-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_reserve" events 8 1'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_reserve' requires arg2 flags to be 0"
    }
    {
        name: "ringbuf-reserve-rejects-dynamic-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_reserve" events 8 $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_reserve' requires arg2 flags to be 0"
    }
    {
        name: "ringbuf-submit-accepts-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf flags ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 3'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-submit-rejects-invalid-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_submit' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "ringbuf-submit-rejects-dynamic-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_submit' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "ringbuf-discard-rejects-invalid-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_discard" $rec 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_discard' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "ringbuf-discard-rejects-dynamic-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_discard" $rec $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_discard' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "ringbuf-reserve-rejects-double-submit"
        category: "helper-state"
        tags: [ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf record already released"
    }
    {
        name: "ringbuf-reserve-rejects-submit-after-discard"
        category: "helper-state"
        tags: [ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_discard" $rec 0'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf record already released"
    }
    {
        name: "ringbuf-dynptr-reserve-submit-balanced"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-user-function-submit-balanced"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def submit [d] {'
            '    helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '    0'
            '  }'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  submit $d'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-user-function-reserve-submit-balanced"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime user-function]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def reserve [d] {'
            '    helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '    0'
            '  }'
            '  def submit [d] {'
            '    helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '    0'
            '  }'
            '  let d = "0123456789abcdef"'
            '  reserve $d'
            '  submit $d'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-reserve-discard-balanced"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-submit-rejects-return-use"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime void-return reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0 | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "void helper 'bpf_ringbuf_submit_dynptr' return value cannot be used"
    }
    {
        name: "ringbuf-dynptr-rejects-leak"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased ringbuf dynptr reservation"
    }
    {
        name: "ringbuf-dynptr-rejects-conditional-release-leak"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased ringbuf dynptr reservation"
    }
    {
        name: "ringbuf-dynptr-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime branch reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  }'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf dynptr reservation already released"
    }
    {
        name: "ringbuf-dynptr-accepts-both-branch-reserve-before-submit"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime phi accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  } else {'
            '    helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  }'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-allows-slot-reuse-after-submit"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-allows-slot-reuse-after-discard"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-rejects-double-submit"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf dynptr reservation already released"
    }
    {
        name: "ringbuf-dynptr-rejects-submit-after-discard"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf dynptr reservation already released"
    }
    {
        name: "ringbuf-dynptr-reserve-rejects-nonzero-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 1 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_reserve_dynptr' requires arg2 flags to be 0"
    }
    {
        name: "ringbuf-dynptr-reserve-rejects-dynamic-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 $flags $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_reserve_dynptr' requires arg2 flags to be 0"
    }
    {
        name: "ringbuf-dynptr-submit-accepts-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 3'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-dynptr-submit-rejects-invalid-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_submit_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "ringbuf-dynptr-submit-rejects-dynamic-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_submit_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "ringbuf-dynptr-discard-rejects-invalid-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_discard_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
]
