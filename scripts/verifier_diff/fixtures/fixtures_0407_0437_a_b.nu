const VERIFIER_DIFF_FIXTURES_0407_0437_A_B = [
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
]
