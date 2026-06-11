const VERIFIER_DIFF_FIXTURES_1219_1250 = [
    {
        name: "source-kfunc-iter-kmem-cache-rejects-next-without-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_next" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_kmem_cache_next' requires a matching bpf_iter_kmem_cache_new"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-leak"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased iter_kmem_cache iterator"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-double-destroy"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_iter_kmem_cache_destroy' requires a matching bpf_iter_kmem_cache_new"
    }
    {
        name: "source-kfunc-iter-kmem-cache-rejects-reinit-after-conditional-new"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  }'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires uninitialized bpf_iter_kmem_cache stack object slot"
    }
    {
        name: "source-kfunc-iter-kmem-cache-accepts-reinit-after-conditional-balanced-lifecycle"
        category: "helper-state"
        tags: [kfunc iter ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let iter = "0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '    kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  }'
            '  kfunc-call "bpf_iter_kmem_cache_new" $iter'
            '  kfunc-call "bpf_iter_kmem_cache_destroy" $iter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-ref-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-task-from-vpid-ref-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_vpid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
        default_test_lane: "dry-run"
    }
    {
        name: "source-kfunc-task-from-vpid-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_vpid" 1)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-task-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let task = (if $selector == 0 { kfunc-call "bpf_task_from_pid" 1 } else { 0 })'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-wrong-pointer-pointee"
        category: "helper-state"
        tags: [kfunc btf source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define opts --kind array --value-type bytes:32 --max-entries 1'
            '  let opts = (0 | map-get opts --kind array)'
            '  let data = $ctx.data'
            '  if $opts {'
            '    kfunc-call "bpf_xdp_get_xfrm_state" $data $opts 32'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_xdp_get_xfrm_state' arg0 expects xdp_md pointer"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-timestamp"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let timestamp = "01234567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx $timestamp)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-timestamp-copied-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let timestamp = "01234567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_timestamp" $raw_ctx $timestamp)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-timestamp-user-function-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept user-function]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def read_timestamp [raw_ctx] {'
            '    let timestamp = "01234567"'
            '    let rc = (kfunc-call "bpf_xdp_metadata_rx_timestamp" $raw_ctx $timestamp)'
            '    $rc | count'
            '    0'
            '  }'
            '  read_timestamp $ctx'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-hash"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let hash = "0123"'
            '  let rss_type = "4567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_hash" $ctx $hash $rss_type)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-hash-copied-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let hash = "0123"'
            '  let rss_type = "4567"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_hash" $raw_ctx $hash $rss_type)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-vlan-tag"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let vlan_proto = "01"'
            '  let vlan_tci = "23"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $ctx $vlan_proto $vlan_tci)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-vlan-tag-copied-raw-context"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let vlan_proto = "01"'
            '  let vlan_tci = "23"'
            '  let rc = (kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $raw_ctx $vlan_proto $vlan_tci)'
            '  $rc | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-metadata-rejects-non-xdp"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let timestamp = "01234567"'
            '  kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx $timestamp'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_xdp_metadata_rx_timestamp' is only valid in xdp programs"
    }
    {
        name: "source-kfunc-xdp-metadata-rejects-packet-output-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: '{|ctx| kfunc-call "bpf_xdp_metadata_rx_timestamp" $ctx $ctx.data; "pass" }'
        local: "reject"
        kernel: "skip"
        error_contains: "got Packet"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-hash-rejects-packet-rss-type-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let hash = "0123"'
            '  kfunc-call "bpf_xdp_metadata_rx_hash" $ctx $hash $ctx.data'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "got Packet"
    }
    {
        name: "source-kfunc-xdp-metadata-rx-vlan-tag-rejects-packet-tci-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp metadata source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let vlan_proto = "01"'
            '  kfunc-call "bpf_xdp_metadata_rx_vlan_tag" $ctx $vlan_proto $ctx.data'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "got Packet"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '  if $state {'
            '    kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-release-accepts-acquire-or-null-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (if $selector == 0 { kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32 } else { 0 })'
            '  if $state {'
            '    kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-copied-raw-context-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source accept context-alias]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let raw_ctx = $ctx'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (kfunc-call "bpf_xdp_get_xfrm_state" $raw_ctx $opts 32)'
            '  if $state {'
            '    kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-user-function-raw-context-release"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source accept user-function]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_state [raw_ctx] {'
            '    let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '    let state = (kfunc-call "bpf_xdp_get_xfrm_state" $raw_ctx $opts 32)'
            '    if $state {'
            '      kfunc-call "bpf_xdp_xfrm_state_release" $state'
            '    }'
            '    0'
            '  }'
            '  get_state $ctx'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-small-opts-buffer"
        category: "helper-state"
        tags: [kfunc btf xdp bounds source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define opts --kind array --value-type bytes:16 --max-entries 1'
            '  let opts = (0 | map-get opts --kind array)'
            '  if $opts {'
            '    let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '    if $state { kfunc-call "bpf_xdp_xfrm_state_release" $state }'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_xdp_get_xfrm_state opts requires 32 bytes"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-non-xdp-program"
        category: "helper-state"
        tags: [kfunc btf xdp program-policy source reject]
        requires: [kernel-btf]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  map-define opts --kind array --value-type bytes:32 --max-entries 1'
            '  let opts = (0 | map-get opts --kind array)'
            '  if $opts {'
            '    let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '    if $state { kfunc-call "bpf_xdp_xfrm_state_release" $state }'
            '  }'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_xdp_get_xfrm_state' is only valid in xdp programs"
    }
    {
        name: "source-kfunc-xdp-xfrm-state-rejects-leak"
        category: "helper-state"
        tags: [kfunc btf xdp ref-lifetime source reject]
        requires: [kernel-btf]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let opts = { error: 0, netns_id: -1, mark: 0, daddr: [0 0 0 0], spi: 0, proto: 50, family: 2 }'
            '  let state = (kfunc-call "bpf_xdp_get_xfrm_state" $ctx $opts 32)'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-new-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-drop-accepts-new-or-null-release"
        category: "helper-state"
        tags: [kfunc object ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let obj = (if $selector == 0 { kfunc-call "bpf_obj_new_impl" 1 0 } else { 0 })'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-obj-new-rejects-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
]
