const VERIFIER_DIFF_FIXTURES_1407_1421_B = [
    {
        name: "source-kfunc-crypto-ctx-create-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-acquire-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      let owned = (kfunc-call "bpf_crypto_ctx_acquire" $crypto)'
            '      if $owned {'
            '        $owned | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-acquire-rejects-owned-leak"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      let owned = (kfunc-call "bpf_crypto_ctx_acquire" $crypto)'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-crypto-ctx-release-accepts-create-or-null-release"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime phi source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    let crypto = (if $selector == 0 { kfunc-call "bpf_crypto_ctx_create" $params 408 $err } else { 0 })'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-create-record-field-err"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime record source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let rec = { err: "00000000" }'
            '  let err = $rec.err'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-crypto-ctx-create-rejects-leak"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      1 | count'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-crypto-encrypt-accepts-tracked-ctx"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst $siv'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
