const VERIFIER_DIFF_FIXTURES_1219_1250_B_B = [
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
