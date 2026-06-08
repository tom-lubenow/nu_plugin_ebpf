const VERIFIER_DIFF_FIXTURES_0376_0500 = [
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
    {
        name: "ringbuf-dynptr-discard-rejects-dynamic-wakeup-flags"
        category: "helper-state"
        tags: [ringbuf dynptr flags ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_discard_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits"
    }
    {
        name: "dynptr-data-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_dynptr_data" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires initialized dynptr stack object"
    }
    {
        name: "dynptr-from-mem-initializes-map-value"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    let ptr = (helper-call "bpf_dynptr_data" $d 0 4)'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-from-mem-rejects-reinitialize"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_reinit_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_reinit_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-from-mem-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 1 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' requires arg2 flags to be 0"
    }
    {
        name: "dynptr-from-mem-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 $flags $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' requires arg2 flags to be 0"
    }
    {
        name: "dynptr-from-mem-accepts-both-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_join_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_join_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    } else {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_data" $d 0 4'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-from-mem-rejects-one-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_join_partial_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_join_partial_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_data" $d 0 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_data' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-from-mem-rejects-reinit-after-one-branch-initialization"
        category: "helper-state"
        tags: [dynptr phi reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_reinit_join_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_reinit_join_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    }'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-read-write-initialized-from-mem"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_rw_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_rw_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "dynptr-read-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-read-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_read_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_read_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' requires arg4 flags to be 0"
    }
    {
        name: "dynptr-read-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_read_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_read_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' requires arg4 flags to be 0"
    }
    {
        name: "dynptr-read-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 ringbuf dynptr reservation already released"
    }
    {
        name: "dynptr-write-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "wxyz"'
            '  helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-write-rejects-nonzero-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_write_flag_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_write_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' requires arg4 flags to be 0 for modeled dynptr sources"
    }
    {
        name: "dynptr-write-rejects-dynamic-flags"
        category: "helper-state"
        tags: [dynptr flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_write_dynamic_flag_buffers 0 --kind array'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  let entry = (0 | map-get dynptr_write_dynamic_flag_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' requires arg4 flags to be 0 for modeled dynptr sources"
    }
    {
        name: "dynptr-write-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "wxyz"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' arg0 ringbuf dynptr reservation already released"
    }
    {
        name: "dynptr-data-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [dynptr ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_dynptr_data" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_data' arg0 ringbuf dynptr reservation already released"
    }
    {
        name: "source-helper-copy-from-user-accepts-user-src"
        category: "helper-state"
        tags: [helper copy-user accept]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    helper-call "bpf_copy_from_user" $dst 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-copy-from-user-task-accepts-current-task"
        category: "helper-state"
        tags: [helper copy-user accept]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    helper-call "bpf_copy_from_user_task" $dst 8 $ptr $ctx.current_task 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-copy-from-user-task-rejects-dynamic-flags"
        category: "helper-state"
        tags: [helper copy-user flags reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "0123456789abcdef"'
            '    let flags = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_copy_from_user_task" $dst 8 $ptr $ctx.current_task $flags'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_copy_from_user_task' requires arg4 = 0"
    }
    {
        name: "source-helper-copy-from-user-accepts-zero-size-null-dst"
        category: "helper-state"
        tags: [helper copy-user zero-size accept]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    helper-call "bpf_copy_from_user" 0 0 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-copy-from-user-rejects-null-dst-nonzero-size"
        category: "helper-state"
        tags: [helper copy-user zero-size reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    helper-call "bpf_copy_from_user" 0 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 148 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "source-helper-copy-from-user-rejects-null-dst-dynamic-size"
        category: "helper-state"
        tags: [helper copy-user zero-size dynamic reject]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let size = (helper-call "bpf_get_prandom_u32")'
            '    helper-call "bpf_copy_from_user" 0 $size $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 148 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "source-helper-copy-from-user-rejects-stack-src"
        category: "helper-state"
        tags: [helper copy-user reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "abcdefgh"'
            '  helper-call "bpf_copy_from_user" $dst 8 $src'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper copy_from_user src expects pointer in [User]"
    }
    {
        name: "source-helper-probe-read-accepts-kernel-src"
        category: "helper-state"
        tags: [helper probe-read accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read" $dst 8 $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-str-accepts-kprobe-context"
        category: "helper-state"
        tags: [helper probe-read string accept source metadata]
        target: "kprobe:__x64_sys_getpid"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read_str" $dst 8 $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-kernel-accepts-kernel-src"
        category: "helper-state"
        tags: [helper probe-read kernel accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read_kernel" $dst 8 $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-kernel-str-accepts-kernel-src"
        category: "helper-state"
        tags: [helper probe-read kernel string accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read_kernel_str" $dst 8 $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-user-accepts-user-src"
        category: "helper-state"
        tags: [helper probe-read user accept source metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "01234567"'
            '    helper-call "bpf_probe_read_user" $dst 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-user-str-accepts-user-src"
        category: "helper-state"
        tags: [helper probe-read user string accept source metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let dst = "01234567"'
            '    helper-call "bpf_probe_read_user_str" $dst 8 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-probe-read-user-rejects-stack-src"
        category: "helper-state"
        tags: [helper probe-read user reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  let src = "abcdefgh"'
            '  helper-call "bpf_probe_read_user" $dst 8 $src'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper probe_read src expects pointer in [User]"
    }
    {
        name: "source-helper-probe-read-rejects-xdp"
        category: "helper-state"
        tags: [helper probe-read program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let dst = "01234567"'
            '  helper-call "bpf_probe_read" $dst 8 $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_probe_read' is only valid"
    }
    {
        name: "source-helper-current-identity-and-clock-helpers"
        category: "helper-state"
        tags: [helper current time accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_current_pid_tgid"'
            '  helper-call "bpf_get_current_uid_gid"'
            '  helper-call "bpf_get_current_task"'
            '  helper-call "bpf_get_current_task_btf"'
            '  helper-call "bpf_get_smp_processor_id"'
            '  helper-call "bpf_get_numa_node_id"'
            '  helper-call "bpf_jiffies64"'
            '  helper-call "bpf_ktime_get_boot_ns"'
            '  helper-call "bpf_ktime_get_tai_ns"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-current-comm-accepts-map-buffer"
        category: "helper-state"
        tags: [helper current comm map-bounds accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define comm_buf_ok --kind array --value-type bytes:16 --max-entries 1'
            '  let dst = (0 | map-get comm_buf_ok)'
            '  if $dst {'
            '    helper-call "bpf_get_current_comm" $dst 16'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-current-comm-rejects-short-map-buffer"
        category: "helper-state"
        tags: [helper current comm map-bounds reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define comm_buf_short --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get comm_buf_short)'
            '  if $dst {'
            '    helper-call "bpf_get_current_comm" $dst 16'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_current_comm dst requires 16 bytes"
    }
    {
        name: "source-helper-get-current-comm-rejects-dynamic-short-map-buffer"
        category: "helper-state"
        tags: [helper current comm map-bounds dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define comm_buf_dyn_short --kind array --value-type bytes:8 --max-entries 1'
            '  let dst = (0 | map-get comm_buf_dyn_short)'
            '  if $dst {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 8 } else { 16 })'
            '    helper-call "bpf_get_current_comm" $dst $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_current_comm dst requires 16 bytes"
    }
    {
        name: "xdp-ktime-get-coarse-helper"
        category: "helper-state"
        tags: [helper time accept source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ktime_get_coarse_ns"'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-ktime-get-coarse-rejects-raw-tracepoint"
        category: "helper-state"
        tags: [helper time program-policy reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ktime_get_coarse_ns"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ktime_get_coarse_ns' is only valid"
    }
    {
        name: "source-helper-current-cgroup-namespace-helpers"
        category: "helper-state"
        tags: [helper current cgroup namespace accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_ok --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata_ok)'
            '  helper-call "bpf_get_current_cgroup_id"'
            '  helper-call "bpf_get_current_ancestor_cgroup_id" 0'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-short-map-buffer"
        category: "helper-state"
        tags: [helper current namespace map-bounds reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_short --kind array --value-type bytes:4 --max-entries 1'
            '  let ns = (0 | map-get nsdata_short)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_ns_current_pid_tgid nsdata requires 8 bytes"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-dynamic-short-map-buffer"
        category: "helper-state"
        tags: [helper current namespace map-bounds dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_dyn_short --kind array --value-type bytes:4 --max-entries 1'
            '  let ns = (0 | map-get nsdata_dyn_short)'
            '  if $ns {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let size = (if $selector == 0 { 4 } else { 8 })'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper get_ns_current_pid_tgid nsdata requires 8 bytes"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-invalid-size"
        category: "helper-state"
        tags: [helper current namespace size reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_ok --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata_ok)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8"
    }
    {
        name: "source-helper-get-ns-current-pid-tgid-rejects-dynamic-size"
        category: "helper-state"
        tags: [helper current namespace size dynamic reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nsdata_dynamic --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata_dynamic)'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns $size'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8"
    }
    {
        name: "source-helper-tracing-context-cookie-helpers"
        category: "helper-state"
        tags: [helper tracing context-cookie accept source metadata]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_func_ip" $ctx'
            '  helper-call "bpf_get_attach_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tracing-context-cookie-rejects-xdp"
        category: "helper-state"
        tags: [helper tracing context-cookie program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_func_ip" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_func_ip' is only valid"
    }
    {
        name: "source-helper-tc-egress-skb-metadata-helpers"
        category: "helper-state"
        tags: [helper tc skb metadata egress accept source]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_cgroup_classid" $ctx'
            '  helper-call "bpf_get_route_realm" $ctx'
            '  helper-call "bpf_skb_cgroup_id" $ctx'
            '  helper-call "bpf_skb_ancestor_cgroup_id" $ctx 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tc-ingress-skb-cgroup-classid"
        category: "helper-state"
        tags: [helper tc skb metadata ingress accept source]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_classid" $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-tc-skb-metadata-rejects-ingress-egress-only"
        category: "helper-state"
        tags: [helper tc skb metadata egress-only reject source]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_route_realm" $ctx'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_route_realm' is only valid in tc/tcx egress programs"
    }
    {
        name: "source-helper-tc-skb-metadata-rejects-xdp"
        category: "helper-state"
        tags: [helper tc skb metadata program-policy reject source]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_id" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_skb_cgroup_id' is only valid in tc_action, tc, tcx, and netkit programs"
    }
    {
        name: "source-helper-socket-cookie-accepts-socket-filter-context"
        category: "helper-state"
        tags: [helper socket cookie accept source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-returned-socket-filter-context"
        category: "helper-state"
        tags: [helper socket cookie accept user-function source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  def get_ctx [event] { $event }'
            '  let raw_ctx = (get_ctx $ctx)'
            '  helper-call "bpf_get_socket_cookie" $raw_ctx'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-fentry-socket-arg"
        category: "helper-state"
        tags: [helper socket cookie tracing accept source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx.arg0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-accepts-fentry-null"
        category: "helper-state"
        tags: [helper socket cookie tracing "null" accept source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-cookie-rejects-fentry-raw-context"
        category: "helper-state"
        tags: [helper socket cookie tracing raw-context reject source metadata]
        requires: [kernel-btf]
        target: "fentry:tcp_connect"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_cookie' arg0 expects socket pointer in fentry programs"
    }
    {
        name: "source-helper-socket-cookie-rejects-socket-filter-null"
        category: "helper-state"
        tags: [helper socket cookie "null" reject source metadata]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 46 arg0 expects pointer"
    }
    {
        name: "source-helper-socket-cookie-rejects-sk-lookup"
        category: "helper-state"
        tags: [helper socket cookie program-policy reject source metadata]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_cookie' is only valid"
    }
    {
        name: "source-helper-socket-uid-accepts-cgroup-skb"
        category: "helper-state"
        tags: [helper socket uid cgroup-skb accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_uid" $ctx'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-uid-accepts-tc"
        category: "helper-state"
        tags: [helper socket uid tc accept source metadata]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_uid" $ctx'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-socket-uid-rejects-xdp"
        category: "helper-state"
        tags: [helper socket uid program-policy reject source metadata]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_socket_uid" $ctx'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_get_socket_uid' is only valid in socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
    }
    {
        name: "source-helper-netns-cookie-accepts-cgroup-sockopt"
        category: "helper-state"
        tags: [helper netns cookie cgroup-sockopt accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_netns_cookie" $ctx'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-helper-netns-cookie-accepts-sk-msg"
        category: "helper-state"
        tags: [helper netns cookie sk-msg accept source metadata]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_netns_cookie" $ctx'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
