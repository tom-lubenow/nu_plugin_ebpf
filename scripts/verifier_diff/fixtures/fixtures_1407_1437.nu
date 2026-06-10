const VERIFIER_DIFF_FIXTURES_1407_1437 = [
    {
        name: "source-kfunc-path-d-path-rejects-stack-path"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $buf $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg0 expects kernel pointer"
    }
    {
        name: "source-kfunc-path-d-path-rejects-kernel-buffer"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $ctx.arg0 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc path_d_path buffer expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-path-d-path-rejects-small-buffer"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 64'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc path_d_path buffer requires 64 bytes"
    }
    {
        name: "source-kfunc-path-d-path-rejects-zero-size"
        category: "helper-state"
        tags: [kfunc file path source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg2 must be > 0"
    }
    {
        name: "source-kfunc-path-d-path-rejects-dynamic-zero-size"
        category: "helper-state"
        tags: [kfunc file path source dynamic branch reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let buf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  let size = (if $selector == 0 { 0 } else { 64 })'
            '  kfunc-call "bpf_path_d_path" $ctx.arg0.f_path $buf $size'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_path_d_path' arg2 must be > 0"
    }
    {
        name: "source-kfunc-crypto-ctx-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_crypto_ctx_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects crypto_ctx reference, got task reference"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $task {'
            '    kfunc-call "bpf_crypto_encrypt" $task $src $dst $siv'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 expects crypto_ctx reference, got task reference"
    }
    {
        name: "source-kfunc-crypto-ctx-create-rejects-kernel-params"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let err = "00000000"'
            '  if $task {'
            '    kfunc-call "bpf_crypto_ctx_create" $task 408 $err'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_ctx_create params expects pointer in [Stack, Map], got Kernel"
    }
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
    {
        name: "source-kfunc-crypto-decrypt-accepts-tracked-ctx"
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
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst $siv'
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
        name: "source-kfunc-crypto-encrypt-allows-null-siv"
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
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst 0'
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
        name: "source-kfunc-crypto-encrypt-allows-zero-vreg-siv"
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
            '  let siv = 0'
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
    {
        name: "source-kfunc-crypto-encrypt-rejects-nonzero-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_encrypt" $crypto $src $dst 7'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-nonzero-vreg-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = 7'
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
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-decrypt-allows-null-siv"
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
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst 0'
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
        name: "source-kfunc-crypto-decrypt-rejects-nonzero-siv"
        category: "helper-state"
        tags: [kfunc crypto ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let src = "abcdefghijklmnop"'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  if $params {'
            '    let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '    if $crypto {'
            '      kfunc-call "bpf_crypto_decrypt" $crypto $src $dst 9'
            '      $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_crypto_decrypt' arg3 expects null (0) or pointer"
    }
    {
        name: "source-kfunc-crypto-encrypt-rejects-kernel-src"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    if $task {'
            '      let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '      if $crypto {'
            '        kfunc-call "bpf_crypto_encrypt" $crypto $task $dst $siv'
            '        $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_encrypt src expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-crypto-decrypt-rejects-kernel-src"
        category: "helper-state"
        tags: [kfunc crypto source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  map-define crypto_params --kind array --value-type "bytes:512" --max-entries 1'
            '  let params = (0 | map-get crypto_params --kind array)'
            '  let err = "00000000"'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  let dst = "ABCDEFGHIJKLMNOP"'
            '  let siv = "0000000000000000"'
            '  if $params {'
            '    if $task {'
            '      let crypto = (kfunc-call "bpf_crypto_ctx_create" $params 408 $err)'
            '      if $crypto {'
            '        kfunc-call "bpf_crypto_decrypt" $crypto $task $dst $siv'
            '        $crypto | kfunc-call "bpf_crypto_ctx_release"'
            '      }'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc bpf_crypto_decrypt src expects pointer in [Stack, Map], got Kernel"
    }
    {
        name: "source-kfunc-cgroup-acquire-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-acquire-rejects-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cgroup-release-accepts-both-branch-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-one-branch-release-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
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
        name: "source-kfunc-cgroup-release-rejects-release-after-conditional-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime branch source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    if $ctx.pid {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_cgroup_release' arg0 reference already released"
    }
    {
        name: "source-kfunc-cgroup-release-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    kfunc-call "bpf_cgroup_release" $task'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects cgroup reference, got task reference"
    }
    {
        name: "source-kfunc-cgroup-from-id-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
