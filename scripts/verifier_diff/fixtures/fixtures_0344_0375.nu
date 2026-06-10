const VERIFIER_DIFF_FIXTURES_0344_0375 = [
    {
        name: "map-define-hash-of-maps-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_hash --kind hash-of-maps)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-hash-of-maps-inferred-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map kind-inference accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_hash)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-rejects-missing-inner-map"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --inner-map"
    }
    {
        name: "map-define-map-in-map-rejects-self-inner-map"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --inner-map outer_array --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use itself as its inner map template"
    }
    {
        name: "map-define-map-in-map-rejects-nested-inner-template"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define leaf_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define inner_outer --kind array-of-maps --inner-map leaf_seen --max-entries 4'
            '  map-define outer_array --kind array-of-maps --inner-map inner_outer --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "must name a previously declared inner map with --value-type"
    }
    {
        name: "map-define-map-in-map-rejects-outer-value-type"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --value-type u64 --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "--value-type is not supported for map-in-map outer map"
    }
    {
        name: "map-define-hash-of-maps-rejects-missing-key-type"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "hash-of-maps requires --key-type"
    }
    {
        name: "queue-map-push-peek-record"
        category: "maps"
        tags: [maps queue map-push map-peek records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = (map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stack-map-push-pop-record"
        category: "maps"
        tags: [maps stack map-push map-pop records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = (map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-map-update-delete-helpers"
        category: "maps"
        tags: [maps helper-call map-update map-delete accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_update_elem" seen $key $value 0'
            '  helper-call "bpf_map_delete_elem" seen $key'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-map-update-rejects-invalid-flags"
        category: "maps"
        tags: [maps helper-call map-update flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_update_elem" seen $key $value 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags"
    }
    {
        name: "raw-map-update-rejects-dynamic-flags"
        category: "maps"
        tags: [maps helper-call map-update flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let key = "abcd"'
            '  let value = "abcdefgh"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_map_update_elem" seen $key $value $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_update_elem' requires arg3 flags"
    }
    {
        name: "raw-queue-map-push-peek-pop-helpers"
        category: "maps"
        tags: [maps queue helper-call map-push map-peek map-pop accept source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 0 --kind queue'
            '  helper-call "bpf_map_peek_elem" recent_raw $value --kind queue'
            '  helper-call "bpf_map_pop_elem" recent_raw $value --kind queue'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-queue-map-push-rejects-invalid-flags"
        category: "maps"
        tags: [maps queue helper-call map-push flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  helper-call "bpf_map_push_elem" recent_raw $value 4 --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags"
    }
    {
        name: "raw-queue-map-push-rejects-dynamic-flags"
        category: "maps"
        tags: [maps queue helper-call map-push flags reject source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = "abcdefgh"'
            '  let flags = (helper-call "bpf_get_prandom_u32")'
            '  helper-call "bpf_map_push_elem" recent_raw $value $flags --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_map_push_elem' requires arg2 flags"
    }
    {
        name: "bloom-filter-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push seen_args --kind bloom-filter'
            '  $ctx.arg0 | map-contains seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "per-cpu-hash-map-put-get"
        category: "maps"
        tags: [maps per-cpu-hash map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put cpu_seen 0 --kind per-cpu-hash'
            '  let entry = (0 | map-get cpu_seen --kind per-cpu-hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "lru-per-cpu-hash-map-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put lru_cpu_seen 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_seen --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage task-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-delete"
        category: "maps"
        tags: [maps local-storage task-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-storage-map-contains"
        category: "maps"
        tags: [maps local-storage task-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  if ($ctx.task | map-contains task_state --kind task-storage) {'
            '    1 | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-contains"
        category: "maps"
        tags: [maps local-storage sk-storage map-contains accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-contains sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage sk-storage map-get accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  let state = ($ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "sk-storage-map-delete"
        category: "maps"
        tags: [maps local-storage sk-storage map-delete accept]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  if $sk {'
            '    $sk | map-delete sock_state --kind sk-storage'
            '  }'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-delete"
        category: "maps"
        tags: [maps local-storage inode-storage map-delete accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "inode-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage inode-storage map-get accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-contains"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "cgrp-storage-map-delete"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-sk-storage-get-helper"
        category: "maps"
        tags: [maps local-storage sk-storage helper-call accept source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_storage_get" sock_state $ctx.sk 0 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-task-storage-get-helper"
        category: "maps"
        tags: [maps local-storage task-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_task_storage_get" task_state $ctx.task 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-inode-storage-get-helper"
        category: "maps"
        tags: [maps local-storage inode-storage helper-call accept source metadata]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  helper-call "bpf_inode_storage_get" inode_state $ctx.arg.file.f_inode 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
