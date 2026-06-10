const VERIFIER_DIFF_FIXTURES_0407_0437 = [
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
