const PROGRAM_SURFACE_PACKET_KERNEL_FEATURE_EXPECTATIONS = [
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
]

let PROGRAM_SURFACE_PACKET_SOCKET_KERNEL_FEATURE_EXPECTATIONS = (
    $PROGRAM_SURFACE_PACKET_KERNEL_FEATURE_EXPECTATIONS
    | append $PROGRAM_SURFACE_SOCKET_REDIRECT_KERNEL_FEATURE_EXPECTATIONS
)
