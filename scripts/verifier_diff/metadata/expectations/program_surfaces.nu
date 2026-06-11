const PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let text = "tail-call random int read-str read-kernel-str | emit | count | histogram start-timer stop-timer map-get map-put map-delete map-contains map-push map-peek map-pop redirect-map assign-socket adjust-message --pull adjust-packet --head redirect-socket redirect --peer"'
            '  # tail-call random int read-str read-kernel-str | emit | count | histogram start-timer stop-timer map-get map-put map-delete map-contains map-push map-peek map-pop redirect-map assign-socket adjust-message --pull adjust-packet --head redirect-socket redirect --peer'
            '  let ignored = 0 # | tail-call prog 0 | emit | count | histogram | start-timer | stop-timer | adjust-message --pull 0 1 | adjust-packet --head 0 | redirect-socket peers 0 --kind sockhash | redirect --peer'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_redirect_map"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  adjust-packet --meta 0'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_xdp_adjust_head"
            "helper:bpf_xdp_adjust_meta"
            "helper:bpf_xdp_adjust_tail"
        ]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  adjust-packet --head 0'
            '  adjust-packet --tail 0'
            '  adjust-packet --room 0 --mode 0'
            '  "ok"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_skb_pull_data"
            "helper:bpf_skb_change_head"
            "helper:bpf_skb_change_tail"
            "helper:bpf_skb_adjust_room"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  adjust-message --cork 8'
            '  adjust-message --pull 0 1'
            '  adjust-message --push 0 1'
            '  adjust-message --pop 0 1'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_msg_apply_bytes"
            "helper:bpf_msg_cork_bytes"
            "helper:bpf_msg_pull_data"
            "helper:bpf_msg_push_data"
            "helper:bpf_msg_pop_data"
            "helper:bpf_msg_redirect_map"
            "helper:bpf_msg_redirect_hash"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket hash_peers 1'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" 0'
            '  redirect-socket hash_peers "peer-b"'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_sk_redirect_map"
            "helper:bpf_sk_redirect_hash"
        ]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  "select"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_select_reuseport"]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|event|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let text = "$ctx.sk = 0; $ctx.sk == 0"'
            '  # $ctx.sk = 0'
            '  if $ctx.sk == 0 { 0 }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|event|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut writable = (passthrough $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let text = "$ctx.new_value = 1"'
            '  # $ctx.new_value = 1'
            '  if $ctx.new_value == 1 { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc_action:demo"
        program: [
            '{|event|'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  let text = "$event.cb_flags = 1"'
            '  # $event.cb_flags = 1'
            '  if $event.cb_flags == 1 { 0 }'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define task_state --kind task-storage --value-type "record{hits:u64}"'
            '  $ctx.task | map-get task_state --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-contains task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_get"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-delete sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_delete"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_get"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_delete"]
    }
]
