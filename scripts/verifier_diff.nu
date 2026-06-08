#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
source ($REPO_ROOT | path join scripts verifier_diff metadata core_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata tracepoint_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata context_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata expectations.nu)

source ($REPO_ROOT | path join scripts verifier_diff fixtures.nu)

def fail [msg: string] {
    error make { msg: $msg }
}

def path-is-filelike [path: string] {
    let kind = ($path | path type)
    $kind == "file" or $kind == "symlink"
}

def newest-existing [label: string candidates: list<string>] {
    let existing = (
        $candidates
        | where {|candidate| path-is-filelike $candidate }
        | each {|candidate|
            let meta = (ls -D $candidate | first)
            { path: $candidate, modified: $meta.modified }
        }
        | sort-by modified
        | reverse
    )

    if (($existing | length) == 0) {
        fail $"could not find ($label); checked: ($candidates | str join ', ')"
    }

    $existing | get 0.path
}

def newest-modified [label: string paths: list<string>] {
    let existing = (
        $paths
        | where {|path| path-is-filelike $path }
        | each {|path| ls -D $path | first | get modified }
        | sort
        | reverse
    )

    if (($existing | length) == 0) {
        fail $"could not find ($label); checked: ($paths | str join ', ')"
    }

    $existing | get 0
}

def plugin-source-inputs [repo_root: string] {
    let rust_sources = (
        glob ($repo_root | path join "src/**/*.rs")
        | where {|path| not (($path | str contains "/tests/") or ($path | str ends-with "/tests.rs")) }
    )
    $rust_sources | append [
        ($repo_root | path join Cargo.toml)
        ($repo_root | path join Cargo.lock)
        ($repo_root | path join build.rs)
    ]
}

def assert-plugin-fresh [repo_root: string plugin_bin: string] {
    let plugin_modified = (ls -D $plugin_bin | first | get modified)
    let source_modified = (newest-modified "plugin source input" (plugin-source-inputs $repo_root))

    if $source_modified > $plugin_modified {
        fail $"plugin binary appears stale: ($plugin_bin) was modified ($plugin_modified), but plugin source inputs were modified ($source_modified); run `cargo build` or set PLUGIN_BIN"
    }
}

def resolve-plugin-bin [repo_root: string] {
    let override = ($env | get -o PLUGIN_BIN)

    if $override != null {
        if not (path-is-filelike $override) {
            fail $"plugin binary not found: ($override)"
        }
        return $override
    }

    let plugin_bin = (newest-existing "plugin binary" [
        ($repo_root | path join target debug nu_plugin_ebpf)
        ($repo_root | path join target release nu_plugin_ebpf)
    ])

    assert-plugin-fresh $repo_root $plugin_bin
    $plugin_bin
}

def current-nu-bin [] {
    $nu.current-exe
}

def command-exists [name: string] {
    ((which $name | length) > 0)
}

def is-root [] {
    ((^id -u | str trim | into int) == 0)
}

def parse-kernel-version [version: string] {
    let core = ($version | split row "-" | first)
    let parts = ($core | split row ".")
    {
        major: (($parts | get 0) | into int)
        minor: (($parts | get -o 1 | default "0") | into int)
        patch: (($parts | get -o 2 | default "0") | into int)
    }
}

def kernel-version-at-least [current: string required: string] {
    (kernel-version-compare $current $required) >= 0
}

def kernel-version-before [current: string maximum_exclusive: string] {
    (kernel-version-compare $current $maximum_exclusive) < 0
}

def kernel-version-compare [left: string right: string] {
    let have = (parse-kernel-version $left)
    let need = (parse-kernel-version $right)

    if $have.major != $need.major {
        if $have.major > $need.major { return 1 }
        return (-1)
    }
    if $have.minor != $need.minor {
        if $have.minor > $need.minor { return 1 }
        return (-1)
    }
    if $have.patch != $need.patch {
        if $have.patch > $need.patch { return 1 }
        return (-1)
    }

    0
}

def kernel-version-max [versions: list<string>] {
    mut max = ""
    mut has_max = false

    for version in $versions {
        if not $has_max {
            $max = $version
            $has_max = true
        } else if (kernel-version-compare $version $max) > 0 {
            $max = $version
        }
    }

    if $has_max { $max } else { null }
}

def kernel-version-min [versions: list<string>] {
    mut min = ""
    mut has_min = false

    for version in $versions {
        if not $has_min {
            $min = $version
            $has_min = true
        } else if (kernel-version-compare $version $min) < 0 {
            $min = $version
        }
    }

    if $has_min { $min } else { null }
}

def current-kernel-release [] {
    ^uname -r | str trim
}

def run-nu-with-plugin-complete [plugin_bin: string code: string] {
    run-external (current-nu-bin) "--no-config-file" "--plugins" $"[($plugin_bin)]" "-c" $code | complete
}

def default-local-jobs [] {
    let value = ($env | get -o VERIFIER_DIFF_JOBS)
    if $value == null {
        4
    } else {
        $value | into int
    }
}

def resolve-local-jobs [jobs] {
    let resolved = if $jobs == null { default-local-jobs } else { $jobs }
    if $resolved < 1 {
        fail $"--jobs must be at least 1, got ($resolved)"
    }
    $resolved
}

def fixture-program [fixture] {
    let program = $fixture.program
    if (($program | describe) | str starts-with "list") {
        $program | str join (char nl)
    } else {
        $program
    }
}

def dry-run-describe-code [fixture] {
    let target = ($fixture.target | to nuon)
    let program = (fixture-program $fixture)
    $"ebpf attach --dry-run ($target) ($program) | describe"
}

def dry-run-save-code [fixture output_path: string] {
    let target = ($fixture.target | to nuon)
    let path = ($output_path | to nuon)
    let program = (fixture-program $fixture)
    $"ebpf attach --dry-run ($target) ($program) | save -f ($path)"
}

def combined-output [result] {
    $"($result.stdout)($result.stderr)"
}

def optional [record field fallback] {
    let value = ($record | get -o $field)
    if $value == null { $fallback } else { $value }
}

def append-missing-kernel-features [features additions] {
    mut result = $features

    for feature in $additions {
        let key = ($feature | get key)
        let exists = ($result | any {|existing| ($existing | get key) == $key })
        if not $exists {
            $result = ($result | append $feature)
        }
    }

    $result
}

def map-kind-kernel-feature [kind: string] {
    let matches = ($MAP_KIND_KERNEL_FEATURES | where {|entry| $entry.kind == $kind })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def outside-simple-string? [text: string] {
    let double_parts = ($text | split row "\"")
    let single_parts = ($text | split row "'")
    (($double_parts | length) mod 2) == 1 and (($single_parts | length) mod 2) == 1
}

def line-contains-outside-simple-string? [line: string marker: string] {
    let parts = ($line | split row $marker)
    if ($parts | length) <= 1 {
        return false
    }

    for part in ($parts | enumerate) {
        if $part.index == 0 {
            continue
        }

        let before = ($parts | first $part.index | str join $marker)
        if (outside-simple-string? $before) {
            return true
        }
    }

    false
}

def marker-tails-outside-simple-string [line: string marker: string] {
    let trimmed = ($line | str trim)
    if $trimmed == "" or ($trimmed | str starts-with "#") {
        return []
    }
    if not ($trimmed | str contains $marker) {
        return []
    }

    let parts = ($trimmed | split row $marker)
    if ($parts | length) <= 1 {
        return []
    }

    mut tails = []
    for part in ($parts | enumerate) {
        if $part.index == 0 {
            continue
        }

        let before = ($parts | first $part.index | str join $marker)
        if (outside-simple-string? $before) and not (line-contains-outside-simple-string? $before "#") {
            $tails = ($tails | append $part.item)
        }
    }

    $tails
}

def line-contains-code-marker? [line: string marker: string] {
    not ((marker-tails-outside-simple-string $line $marker) | is-empty)
}

def command-tail-after-token [raw_after: string] {
    if $raw_after == "" {
        return ""
    }
    if ($raw_after | str starts-with " ") {
        return ($raw_after | str substring 1..)
    }
    for delimiter in [")" "}" "]" ";"] {
        if ($raw_after | str starts-with $delimiter) {
            return ""
        }
    }

    null
}

def command-invocation-tails [line: string command: string] {
    let trimmed = ($line | str trim)
    if $trimmed == "" or ($trimmed | str starts-with "#") {
        return []
    }
    if not ($trimmed | str contains $command) {
        return []
    }

    mut tails = []
    let command_len = ($command | str length)
    if ($trimmed | str starts-with $command) {
        let tail = (command-tail-after-token ($trimmed | str substring $command_len..))
        if $tail != null {
            $tails = ($tails | append $tail)
        }
    }

    for prefix in ["| " "; " "{ " "( " "("] {
        let marker = $"($prefix)($command)"
        let parts = ($trimmed | split row $marker)
        if ($parts | length) <= 1 {
            continue
        }

        for part in ($parts | enumerate) {
            if $part.index == 0 {
                continue
            }

            let before = ($parts | first $part.index | str join $marker)
            if not (outside-simple-string? $before) {
                continue
            }
            if (line-contains-outside-simple-string? $before "#") {
                continue
            }

            let tail = (command-tail-after-token $part.item)
            if $tail != null {
                $tails = ($tails | append $tail)
            }
        }
    }

    $tails
}

def line-invokes-command? [line: string command: string] {
    not ((command-invocation-tails $line $command) | is-empty)
}

def line-invokes-command-with-tail-prefix? [line: string command: string tail_prefix: string] {
    for tail in (command-invocation-tails $line $command) {
        if ($tail | str trim | str starts-with $tail_prefix) {
            return true
        }
    }

    false
}

def source-invokes-command? [source: string command: string] {
    if not ($source | str contains $command) {
        return false
    }

    for line in ($source | lines) {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def source-invokes-command-with-tail-prefix? [source: string command: string tail_prefix: string] {
    if not ($source | str contains $command) {
        return false
    }

    for line in ($source | lines) {
        if (line-invokes-command-with-tail-prefix? $line $command $tail_prefix) {
            return true
        }
    }

    false
}

def source-line-helper-call-name [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    let raw_helper = (($tails | first) | str trim | split row " " | first)
    normalize-helper-name-token $raw_helper
}

def helper-call-map-kind-entry [line: string] {
    let helper_name = (source-line-helper-call-name $line)
    if $helper_name == null {
        return null
    }

    let fixed_matches = ($HELPER_CALL_FIXED_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if not ($fixed_matches | is-empty) {
        return ($fixed_matches | first)
    }

    let explicit_matches = ($HELPER_CALL_EXPLICIT_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if not ($explicit_matches | is-empty) {
        return ($explicit_matches | first)
    }

    null
}

def source-line-helper-call-map-name [line: string entry] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    let tokens = (
        ($tails | first)
        | str trim
        | split row " "
        | each {|token| $token | str trim }
        | where {|token| $token != "" }
    )
    let arg_idx = (($entry | get map_arg) + 1)
    if $arg_idx >= ($tokens | length) {
        return null
    }

    let name = (normalize-map-name-token ($tokens | get $arg_idx))
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def helper-call-effective-map-kind [line: string bindings] {
    let entry = (helper-call-map-kind-entry $line)
    if $entry == null {
        return null
    }

    let fixed_kind = ($entry | get -o kind)
    if $fixed_kind != null and $fixed_kind != "" {
        return $fixed_kind
    }

    let supported_kinds = ($entry | get -o kinds | default [])
    let explicit_kind = (source-line-map-kind $line "")
    if $explicit_kind != "" {
        if $explicit_kind in $supported_kinds {
            return $explicit_kind
        }
        return null
    }

    let map_name = (source-line-helper-call-map-name $line $entry)
    let inferred_kind = (map-kind-binding $bindings $map_name)
    if $inferred_kind != null and ($inferred_kind in $supported_kinds) {
        return $inferred_kind
    }

    null
}

def helper-call-map-kind-kernel-feature [line: string bindings] {
    let kind = (helper-call-effective-map-kind $line $bindings)
    if $kind == null or $kind == "" {
        return null
    }

    map-kind-kernel-feature $kind
}

def source-line-map-kind [line: string default_kind: string] {
    for raw_tail in (marker-tails-outside-simple-string $line "--kind ") {
        let raw_kind = ($raw_tail | str trim | split row " " | first)
        return (normalize-map-kind-token $raw_kind)
    }

    $default_kind
}

def source-line-command-map-name [line: string command: string] {
    let tails = (command-invocation-tails $line $command)
    if ($tails | is-empty) {
        return null
    }

    let raw_name = (($tails | first) | str trim | split row " " | first)
    let name = (normalize-map-name-token $raw_name)
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def source-line-map-kind-surface [line: string] {
    for command in [
        "map-define"
        "map-get"
        "map-put"
        "map-delete"
        "map-contains"
        "map-push"
        "map-peek"
        "map-pop"
        "redirect-map"
        "redirect-socket"
    ] {
        if (line-invokes-command? $line $command) {
            return {
                command: $command
                name: (source-line-command-map-name $line $command)
            }
        }
    }

    null
}

def map-command-default-kind [command: string] {
    if $command in ["map-define" "map-get" "map-put" "map-delete" "map-contains"] {
        "hash"
    } else {
        ""
    }
}

def map-kind-binding [bindings name] {
    if $name == null or $name == "" {
        return null
    }

    let matches = ($bindings | where {|entry| $entry.name == $name })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get kind
    }
}

def bind-map-kind [bindings name kind] {
    if $name == null or $name == "" or $kind == null or $kind == "" {
        return $bindings
    }

    $bindings
    | where {|entry| $entry.name != $name }
    | append { name: $name kind: $kind }
}

def source-line-effective-map-kind [line: string bindings] {
    let surface = (source-line-map-kind-surface $line)
    if $surface == null {
        return null
    }

    let explicit_kind = (source-line-map-kind $line "")
    if $explicit_kind != "" {
        return $explicit_kind
    }

    let name = ($surface | get name)
    if $name == null {
        return null
    }

    let inferred_kind = (map-kind-binding $bindings $name)
    if $inferred_kind != null {
        return $inferred_kind
    }

    let default_kind = (map-command-default-kind ($surface | get command))
    if $default_kind == "" {
        null
    } else {
        $default_kind
    }
}

def update-map-kind-bindings-for-line [bindings line: string] {
    let surface = (source-line-map-kind-surface $line)
    if $surface == null {
        return $bindings
    }

    let name = ($surface | get name)
    if $name == null {
        return $bindings
    }

    let kind = (source-line-effective-map-kind $line $bindings)
    bind-map-kind $bindings $name $kind
}

def update-helper-call-map-kind-bindings-for-line [bindings line: string] {
    let entry = (helper-call-map-kind-entry $line)
    if $entry == null {
        return $bindings
    }

    let name = (source-line-helper-call-map-name $line $entry)
    let kind = (helper-call-effective-map-kind $line $bindings)
    bind-map-kind $bindings $name $kind
}

def line-invokes-map-kind-surface? [line: string] {
    for command in [
        "map-define"
        "map-get"
        "map-put"
        "map-delete"
        "map-contains"
        "map-push"
        "map-peek"
        "map-pop"
        "redirect-map"
        "redirect-socket"
    ] {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def generic-map-lookup-kind? [kind: string] {
    $kind in [
        "hash"
        "array"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "per-cpu-array"
        "lru-per-cpu-hash"
    ]
}

def generic-map-update-kind? [kind: string] {
    $kind in [
        "hash"
        "array"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "per-cpu-array"
        "lru-per-cpu-hash"
    ]
}

def generic-map-delete-kind? [kind: string] {
    $kind in [
        "hash"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "lru-per-cpu-hash"
    ]
}

def local-storage-get-helper-kernel-feature [kind: string] {
    if $kind == "sk-storage" {
        return $KERNEL_FEATURE_BPF_SK_STORAGE_GET
    }
    if $kind == "inode-storage" {
        return $KERNEL_FEATURE_BPF_INODE_STORAGE_GET
    }
    if $kind == "task-storage" {
        return $KERNEL_FEATURE_BPF_TASK_STORAGE_GET
    }
    if $kind == "cgrp-storage" {
        return $KERNEL_FEATURE_BPF_CGRP_STORAGE_GET
    }

    null
}

def local-storage-delete-helper-kernel-feature [kind: string] {
    if $kind == "sk-storage" {
        return $KERNEL_FEATURE_BPF_SK_STORAGE_DELETE
    }
    if $kind == "inode-storage" {
        return $KERNEL_FEATURE_BPF_INODE_STORAGE_DELETE
    }
    if $kind == "task-storage" {
        return $KERNEL_FEATURE_BPF_TASK_STORAGE_DELETE
    }
    if $kind == "cgrp-storage" {
        return $KERNEL_FEATURE_BPF_CGRP_STORAGE_DELETE
    }

    null
}

def helper-kernel-feature [name: string] {
    let matches = ($HELPER_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let helper_ids = ($BPF_HELPER_IDS | where {|entry| $entry.name == $name })
    if ($helper_ids | is-empty) {
        return null
    }

    let helper_id = ($helper_ids | first | get id)
    let floors = ($BPF_HELPER_KERNEL_FLOORS_BY_MAX_ID | where {|floor| $helper_id <= $floor.max_id })
    if ($floors | is-empty) {
        return null
    }

    let floor = ($floors | first)
    let min_kernel = ($floor | get min_kernel)
    {
        key: $"helper:($name)"
        min_kernel: $min_kernel
        source: $"https://github.com/torvalds/linux/blob/v($min_kernel)/include/uapi/linux/bpf.h"
    }
}

def kfunc-kernel-feature [name: string] {
    let matches = ($KFUNC_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let fallback = ($KFUNC_KERNEL_FEATURE_FALLBACKS | where {|entry| $entry.name == $name })
    if ($fallback | is-empty) {
        return null
    }

    let entry = ($fallback | first)
    mut feature = {
        key: $"kfunc:($name)"
        min_kernel: ($entry | get min_kernel)
        source: ($entry | get source)
    }

    let max_kernel = ($entry | get -o max_kernel_exclusive)
    if $max_kernel != null and $max_kernel != "" {
        $feature = ($feature | insert max_kernel_exclusive $max_kernel)
        let max_kernel_source = ($entry | get -o max_kernel_exclusive_source)
        if $max_kernel_source != null and $max_kernel_source != "" {
            $feature = ($feature | insert max_kernel_exclusive_source $max_kernel_source)
        }
    }

    $feature
}

def target-uses-bpf-tracing-prog-type [target] {
    let target_text = ($target | default "")
    [
        ($target_text | str starts-with "fentry:")
        ($target_text | str starts-with "fentry.s:")
        ($target_text | str starts-with "fexit:")
        ($target_text | str starts-with "fexit.s:")
        ($target_text | str starts-with "fmod_ret:")
        ($target_text | str starts-with "fmod_ret.s:")
        ($target_text | str starts-with "tp_btf:")
    ] | any {|matches| $matches }
}

def program-kfunc-kernel-feature [name: string target] {
    if $name == "bpf_dynptr_from_skb" and (target-uses-bpf-tracing-prog-type $target) {
        return {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }

    kfunc-kernel-feature $name
}

def sock-ops-context-field-kernel-feature [field: string] {
    if $field in ["op" "reply" "replylong"] {
        return {
            key: $"ctx:($field)"
            min_kernel: "4.14"
            source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
        }
    }

    if $field in [
        "args"
        "is_fullsock"
        "snd_cwnd"
        "srtt_us"
        "cb_flags"
        "state"
        "rtt_min"
        "snd_ssthresh"
        "rcv_nxt"
        "snd_nxt"
        "snd_una"
        "mss_cache"
        "ecn_flags"
        "rate_delivered"
        "rate_interval_us"
        "packets_out"
        "retrans_out"
        "total_retrans"
        "segs_in"
        "data_segs_in"
        "segs_out"
        "data_segs_out"
        "lost_out"
        "sacked_out"
        "sk_txhash"
        "bytes_received"
        "bytes_acked"
    ] {
        return {
            key: $"ctx:($field)"
            min_kernel: "4.16"
            source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
        }
    }

    if $field in ["sk" "sock" "socket"] {
        return {
            key: "ctx:sk"
            min_kernel: "5.3"
            source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
        }
    }

    null
}

def target-context-field-alias-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if $field == "retval" {
        if (
            ($target_text | str starts-with "kretprobe:")
            or ($target_text | str starts-with "kretprobe.multi:")
            or ($target_text | str starts-with "kretsyscall:")
            or ($target_text | str starts-with "uretprobe:")
            or ($target_text | str starts-with "uretprobe.s:")
            or ($target_text | str starts-with "uretprobe.multi:")
            or ($target_text | str starts-with "uretprobe.multi.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_PT_REGS }
        }
        if (
            ($target_text | str starts-with "fexit:")
            or ($target_text | str starts-with "fexit.s:")
            or ($target_text | str starts-with "fmod_ret:")
            or ($target_text | str starts-with "fmod_ret.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE }
        }
    }

    if ($target_text | str starts-with "xdp:") {
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_DATA_END }
        }
        if $field == "ingress_ifindex" or $field == "ifindex" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_INGRESS_IFINDEX }
        }
        if $field == "rx_queue_index" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_RX_QUEUE_INDEX }
        }
    }
    if ($target_text | str starts-with "sk_msg:") {
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA_END }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_FAMILY }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_PORT }
        }
        if $field == "size" or $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
        }
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
        }
    }
    if (
        ($target_text | str starts-with "sk_skb:")
        or ($target_text | str starts-with "sk_skb_parser:")
    ) and ($field in ["sk" "sock" "socket"]) {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    }
    if (
        ($target_text | str starts-with "socket_filter:")
        or ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "cgroup_skb:")
    ) and ($field in ["sk" "sock" "socket"]) {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SKB_SK }
    }
    if ($target_text | str starts-with "sk_reuseport:") {
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END }
        }
        if $field == "eth_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_ETH_PROTOCOL }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL }
        }
        if $field == "bind_inany" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY }
        }
        if $field == "hash" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_HASH }
        }
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_SK }
        }
        if $field == "migrating_sk" or $field == "migrating_socket" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK }
        }
    }
    if ($target_text | str starts-with "sock_ops:") {
        let sock_ops_feature = (sock-ops-context-field-kernel-feature $field)
        if $sock_ops_feature != null {
            return { matched: true, feature: $sock_ops_feature }
        }
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA_END }
        }
    }
    if ($target_text | str starts-with "netfilter:") {
        if $field == "state" or $field == "nf_state" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_STATE }
        }
        if $field == "skb" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_SKB }
        }
        if $field == "hook" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_HOOK }
        }
        if $field == "pf" or $field == "protocol_family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY }
        }
    }
    if ($target_text | str starts-with "lirc_mode2:") {
        if $field == "sample" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_SAMPLE }
        }
        if $field == "value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_VALUE }
        }
        if $field == "mode" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_MODE }
        }
    }
    if ($target_text | str starts-with "perf_event:") {
        if $field == "sample_period" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD }
        }
        if $field == "addr" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_PERF_ADDR }
        }
    }
    if ($target_text | str starts-with "cgroup_device:") {
        if $field == "access_type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS_TYPE }
        }
        if $field == "device_access" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS }
        }
        if $field == "device_type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_TYPE }
        }
        if $field == "major" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_MAJOR }
        }
        if $field == "minor" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_MINOR }
        }
    }
    if ($target_text | str starts-with "cgroup_sysctl:") {
        if $field == "name" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_NAME }
        }
        if $field == "base_name" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME }
        }
        if $field == "current_value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_CURRENT_VALUE }
        }
        if $field == "new_value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_NEW_VALUE }
        }
        if $field == "write" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_WRITE }
        }
        if $field == "file_pos" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_FILE_POS }
        }
    }
    if ($target_text | str starts-with "cgroup_sockopt:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCKOPT_SK }
        }
        if $field == "level" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_LEVEL }
        }
        if $field == "optname" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTNAME }
        }
        if $field == "optlen" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTLEN }
        }
        if $field == "optval" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL }
        }
        if $field == "optval_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL_END }
        }
        if $field == "retval" or $field == "sockopt_retval" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_RETVAL }
        }
    }
    if ($target_text | str starts-with "cgroup_sock:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SK }
        }
        if $field == "bound_dev_if" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_BOUND_DEV_IF }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_FAMILY }
        }
        if $field == "sock_type" or $field == "type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SOCK_TYPE }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_PROTOCOL }
        }
        if $field == "mark" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_MARK }
        }
        if $field == "priority" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_PRIORITY }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_PORT }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
        }
        if $field == "state" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE }
        }
        if $field == "rx_queue_mapping" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_RX_QUEUE_MAPPING }
        }
    }
    if ($target_text | str starts-with "sk_lookup:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_SK }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_FAMILY }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_PROTOCOL }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_PORT }
        }
        if $field == "cookie" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE }
        }
        if $field == "ingress_ifindex" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_INGRESS_IFINDEX }
        }
    }
    if ($target_text | str starts-with "cgroup_sock_addr:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SK }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_FAMILY }
        }
        if $field == "sock_type" or $field == "type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SOCK_TYPE }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_PROTOCOL }
        }
        if $field == "user_family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_FAMILY }
        }
        if $field == "user_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 }
        }
        if $field == "user_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP6 }
        }
        if $field == "user_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_PORT }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            if ($target_text | str ends-with ":sendmsg4") {
                return {
                    matched: true
                    feature: {
                        key: "ctx:local_ip4"
                        min_kernel: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 | get min_kernel)
                        source: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 | get source)
                    }
                }
            }
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            if ($target_text | str ends-with ":sendmsg6") {
                return {
                    matched: true
                    feature: {
                        key: "ctx:local_ip6"
                        min_kernel: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 | get min_kernel)
                        source: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 | get source)
                    }
                }
            }
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_PORT }
        }
        if $field == "msg_src_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 }
        }
        if $field == "msg_src_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 }
        }
    }

    if ($target_text | str starts-with "iter:") {
        let iter_target = ($target_text | split row ":" | get 1)

        if $field == "meta" or $field == "iter_meta" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_META }
        }
        if $field == "task" or $field == "iter_task" {
            if $iter_target == "task_vma" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
            }
            if $iter_target in ["task" "task_file"] {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK }
            }
        }
        if ($field == "fd" or $field == "iter_fd") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FD }
        }
        if ($field == "file" or $field == "iter_file") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FILE }
        }
        if ($field == "vma" or $field == "iter_vma") and $iter_target == "task_vma" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_VMA }
        }
        if ($field == "cgroup" or $field == "iter_cgroup") and $iter_target == "cgroup" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_CGROUP }
        }
        if $field == "map" or $field == "iter_map" {
            if $iter_target == "bpf_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP }
            }
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_MAP }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_MAP }
            }
        }
        if $field == "key" or $field == "iter_key" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_KEY }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_KEY }
            }
        }
        if $field == "value" or $field == "iter_value" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_VALUE }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_VALUE }
            }
        }
        if $field == "sk" or $field == "sock" or $field == "iter_sock" {
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_SOCK }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
            }
        }
        if ($field == "prog" or $field == "iter_prog") and $iter_target == "bpf_prog" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_PROG }
        }
        if ($field == "link" or $field == "iter_link") and $iter_target == "bpf_link" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_LINK }
        }
        if ($field == "sk_common" or $field == "sock_common" or $field == "iter_sk_common") and $iter_target == "tcp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_SK_COMMON }
        }
        if ($field == "udp_sk" or $field == "iter_udp_sk") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_SK }
        }
        if ($field == "unix_sk" or $field == "iter_unix_sk") and $iter_target == "unix" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_SK }
        }
        if $field == "uid" or $field == "iter_uid" {
            if $iter_target == "tcp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_UID }
            }
            if $iter_target == "udp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_UID }
            }
            if $iter_target == "unix" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
            }
        }
        if ($field == "bucket" or $field == "iter_bucket") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_BUCKET }
        }
        if ($field == "rt" or $field == "route" or $field == "ipv6_route" or $field == "iter_ipv6_route") and $iter_target == "ipv6_route" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_IPV6_ROUTE }
        }
        if ($field == "ksym" or $field == "iter_ksym") and $iter_target == "ksym" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KSYM }
        }
        if ($field == "netlink_sk" or $field == "iter_netlink_sk") and $iter_target == "netlink" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_NETLINK_SK }
        }
        if ($field == "cache" or $field == "kmem_cache" or $field == "iter_kmem_cache") and $iter_target == "kmem_cache" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KMEM_CACHE }
        }
        if ($field == "dmabuf" or $field == "iter_dmabuf") and $iter_target == "dmabuf" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_DMABUF }
        }
    }

    { matched: false, feature: null }
}

def context-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if ($target_text | str starts-with "tracepoint:") and not (tracepoint-built-in-context-field? $field) {
        return null
    }

    let target_alias = (target-context-field-alias-kernel-feature $field $target)
    if $target_alias.matched {
        return $target_alias.feature
    }

    let matches = ($CONTEXT_FIELD_KERNEL_FEATURES | where {|entry| $entry.field == $field })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def syscall-tracepoint-fallback-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:syscalls/") {
        return null
    }

    let name = ($target_text | str replace "tracepoint:syscalls/" "")
    let syscall = if ($name | str starts-with "sys_enter_") {
        if $field not-in ["id" "args"] {
            return null
        }
        $name | str replace "sys_enter_" ""
    } else if ($name | str starts-with "sys_exit_") {
        if $field not-in ["id" "ret"] {
            return null
        }
        $name | str replace "sys_exit_" ""
    } else {
        return null
    }

    let min_kernel = if $syscall == "openat2" {
        "5.6"
    } else if $syscall == "faccessat2" {
        "5.8"
    } else if $syscall == "fchmodat2" {
        "6.6"
    } else if $syscall == "close_range" {
        "5.9"
    } else if $syscall == "epoll_pwait2" {
        "5.11"
    } else if $syscall in ["open_tree" "move_mount" "fsmount" "fsopen" "fsconfig" "fspick"] {
        "5.2"
    } else if $syscall == "mount_setattr" {
        "5.12"
    } else if $syscall in ["statmount" "listmount"] {
        "6.8"
    } else if $syscall == "open_tree_attr" {
        "6.15"
    } else if $syscall == "quotactl_fd" {
        "5.14"
    } else if $syscall == "pidfd_send_signal" {
        "5.1"
    } else if $syscall == "pidfd_open" {
        "5.3"
    } else if $syscall == "pidfd_getfd" {
        "5.6"
    } else if $syscall in ["landlock_create_ruleset" "landlock_add_rule" "landlock_restrict_self"] {
        "5.13"
    } else if $syscall in ["lsm_get_self_attr" "lsm_set_self_attr" "lsm_list_modules"] {
        "6.8"
    } else if $syscall in ["setxattrat" "getxattrat" "listxattrat" "removexattrat"] {
        "6.13"
    } else if $syscall == "futex_waitv" {
        "5.16"
    } else if $syscall in ["futex_wake" "futex_wait" "futex_requeue"] {
        "6.7"
    } else if $syscall == "arch_prctl" {
        "5.0"
    } else if $syscall == "map_shadow_stack" {
        "6.6"
    } else if $syscall == "uretprobe" {
        "6.14"
    } else if $syscall == "cachestat" {
        "6.5"
    } else if $syscall == "mseal" {
        "6.10"
    } else if $syscall in ["file_getattr" "file_setattr"] {
        "6.17"
    } else if $syscall == "clone3" {
        "5.3"
    } else if $syscall in ["pkey_mprotect" "pkey_alloc" "pkey_free"] {
        "4.9"
    } else if $syscall in ["io_uring_setup" "io_uring_enter" "io_uring_register"] {
        "5.1"
    } else if $syscall == "io_pgetevents" {
        "4.18"
    } else if $syscall == "memfd_secret" {
        "5.14"
    } else if $syscall == "process_madvise" {
        "5.10"
    } else if $syscall == "process_mrelease" {
        "5.15"
    } else if $syscall == "set_mempolicy_home_node" {
        "5.17"
    } else if $syscall == "rseq" {
        "4.18"
    } else if $syscall == "statx" {
        "4.11"
    } else {
        "4.7"
    }
    let source = if $syscall == "openat2" {
        "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
    } else if $syscall == "faccessat2" {
        "https://github.com/torvalds/linux/blob/v5.8/fs/open.c"
    } else if $syscall == "fchmodat2" {
        "https://github.com/torvalds/linux/blob/v6.6/fs/open.c"
    } else if $syscall == "close_range" {
        "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    } else if $syscall == "epoll_pwait2" {
        "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c"
    } else if $syscall in ["open_tree" "move_mount" "fsmount"] {
        "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    } else if $syscall in ["fsopen" "fsconfig" "fspick"] {
        "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    } else if $syscall == "mount_setattr" {
        "https://github.com/torvalds/linux/blob/v5.12/fs/namespace.c"
    } else if $syscall in ["statmount" "listmount"] {
        "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    } else if $syscall == "open_tree_attr" {
        "https://github.com/torvalds/linux/blob/v6.15/fs/namespace.c"
    } else if $syscall in ["mount" "umount" "pivot_root"] {
        "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    } else if $syscall == "quotactl" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/quota/quota.c"
    } else if $syscall == "quotactl_fd" {
        "https://github.com/torvalds/linux/blob/v5.14/fs/quota/quota.c"
    } else if $syscall == "ustat" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    } else if $syscall == "pidfd_send_signal" {
        "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c"
    } else if $syscall == "pidfd_open" {
        "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c"
    } else if $syscall == "pidfd_getfd" {
        "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c"
    } else if $syscall in ["landlock_create_ruleset" "landlock_add_rule" "landlock_restrict_self"] {
        "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    } else if $syscall in ["lsm_get_self_attr" "lsm_set_self_attr" "lsm_list_modules"] {
        "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    } else if $syscall in ["setxattrat" "getxattrat" "listxattrat" "removexattrat"] {
        "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    } else if $syscall == "futex_waitv" {
        "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c"
    } else if $syscall in ["futex_wake" "futex_wait" "futex_requeue"] {
        "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    } else if $syscall == "arch_prctl" {
        "https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/process_64.c"
    } else if $syscall in ["ioperm" "iopl"] {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    } else if $syscall == "modify_ldt" {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ldt.c"
    } else if $syscall == "rt_sigreturn" {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/signal.c"
    } else if $syscall == "map_shadow_stack" {
        "https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/shstk.c"
    } else if $syscall == "uretprobe" {
        "https://github.com/torvalds/linux/blob/v6.14/arch/x86/kernel/uprobes.c"
    } else if $syscall == "kcmp" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c"
    } else if $syscall == "cachestat" {
        "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c"
    } else if $syscall == "mseal" {
        "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c"
    } else if $syscall in ["file_getattr" "file_setattr"] {
        "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c"
    } else if $syscall == "clone3" {
        "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c"
    } else if $syscall in ["fork" "vfork" "clone" "set_tid_address"] {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    } else if $syscall == "personality" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/exec_domain.c"
    } else if $syscall == "vhangup" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    } else if $syscall == "alarm" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c"
    } else if $syscall in ["pause" "restart_syscall"] {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    } else if $syscall == "syslog" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/printk/printk.c"
    } else if $syscall == "sysfs" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/filesystems.c"
    } else if $syscall in ["pkey_mprotect" "pkey_alloc" "pkey_free"] {
        "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    } else if $syscall in ["io_uring_setup" "io_uring_enter" "io_uring_register"] {
        "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    } else if $syscall == "io_pgetevents" {
        "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c"
    } else if $syscall == "memfd_secret" {
        "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c"
    } else if $syscall == "process_madvise" {
        "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c"
    } else if $syscall == "process_mrelease" {
        "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c"
    } else if $syscall == "set_mempolicy_home_node" {
        "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c"
    } else if $syscall == "rseq" {
        "https://github.com/torvalds/linux/blob/v4.18/kernel/rseq.c"
    } else if $syscall == "statx" {
        "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c"
    } else {
        "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
    }

    {
        key: $"tracepoint:syscalls/($name):field:($field)"
        min_kernel: $min_kernel
        source: $source
    }
}

def source-backed-sys-enter-tracepoint-field-kernel-feature [field: string target specs] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:syscalls/sys_enter_") {
        return null
    }

    let syscall = ($target_text | str replace "tracepoint:syscalls/sys_enter_" "")
    let matches = (
        $specs
        | where {|entry| $syscall in $entry.syscalls and $field in $entry.fields }
    )
    if ($matches | is-empty) {
        return null
    }

    let spec = ($matches | first)
    {
        key: $"tracepoint:syscalls/sys_enter_($syscall):field:($field)"
        min_kernel: $spec.min_kernel
        source: $spec.source
    }
}

def tracepoint-payload-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:") {
        return null
    }
    if (tracepoint-built-in-context-field? $field) {
        return null
    }

    let fallback = (syscall-tracepoint-fallback-field-kernel-feature $field $target)
    if $fallback != null {
        return $fallback
    }

    let source_backed_syscall_specs = (
        $FILE_TRACEPOINT_FIELD_SPECS
        | append $FILE_DATA_TRACEPOINT_FIELD_SPECS
        | append $SOCKET_TRACEPOINT_FIELD_SPECS
        | append $PATH_TRACEPOINT_FIELD_SPECS
        | append $QUOTA_TRACEPOINT_FIELD_SPECS
        | append $PROCESS_TRACEPOINT_FIELD_SPECS
        | append $FD_TRACEPOINT_FIELD_SPECS
        | append $MM_TRACEPOINT_FIELD_SPECS
        | append $TIME_TRACEPOINT_FIELD_SPECS
        | append $IO_URING_TRACEPOINT_FIELD_SPECS
        | append $AIO_TRACEPOINT_FIELD_SPECS
        | append $IOPRIO_TRACEPOINT_FIELD_SPECS
        | append $KEY_TRACEPOINT_FIELD_SPECS
        | append $SIGNAL_TRACEPOINT_FIELD_SPECS
        | append $LANDLOCK_TRACEPOINT_FIELD_SPECS
        | append $LSM_SYSCALL_TRACEPOINT_FIELD_SPECS
        | append $IDENTITY_TRACEPOINT_FIELD_SPECS
        | append $SCHED_TRACEPOINT_FIELD_SPECS
        | append $FUTEX_TRACEPOINT_FIELD_SPECS
        | append $MQUEUE_TRACEPOINT_FIELD_SPECS
        | append $IPC_TRACEPOINT_FIELD_SPECS
        | append $X86_TRACEPOINT_FIELD_SPECS
    )
    let source_backed_feature = (
        source-backed-sys-enter-tracepoint-field-kernel-feature $field $target $source_backed_syscall_specs
    )
    if $source_backed_feature != null {
        return $source_backed_feature
    }

    let matches = (
        $TRACEPOINT_FIELD_KERNEL_FEATURES
        | where {|entry| $entry.target == $target_text and $entry.field == $field }
    )
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def context-field-helper-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if ($target_text | str starts-with "tracepoint:") and not (tracepoint-built-in-context-field? $field) {
        return null
    }
    if $field in ["pid" "tid" "tgid" "pid_tgid" "current_pid_tgid"] {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
    }
    if $field == "current_task" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "task" and not ($target_text | str starts-with "iter:") {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "current_cgroup" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "cgroup" and not ($target_text | str starts-with "iter:") {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field in ["uid" "gid" "uid_gid" "current_uid_gid"] {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID
    }
    if $field == "comm" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_COMM
    }
    if $field in ["cpu" "processor_id" "smp_processor_id"] {
        return $KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID
    }
    if $field in ["numa_node" "numa_node_id"] {
        return $KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID
    }
    if $field in ["random" "prandom_u32"] {
        return $KERNEL_FEATURE_BPF_GET_PRANDOM_U32
    }
    if $field == "cgroup_classid" {
        return $KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID
    }
    if $field == "route_realm" {
        return $KERNEL_FEATURE_BPF_GET_ROUTE_REALM
    }
    if $field == "csum_level" {
        return $KERNEL_FEATURE_BPF_CSUM_LEVEL
    }
    if $field in ["hash_recalc" "recalc_hash"] {
        return $KERNEL_FEATURE_BPF_GET_HASH_RECALC
    }
    if $field == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID
    }
    if $field == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_ANCESTOR_CGROUP_ID
    }
    if $field == "skb_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SKB_CGROUP_ID
    }
    if $field == "skb_ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SKB_ANCESTOR_CGROUP_ID
    }
    if $field == "socket_cookie" {
        return $KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE
    }
    if $field == "socket_uid" {
        return $KERNEL_FEATURE_BPF_GET_SOCKET_UID
    }
    if $field == "netns_cookie" {
        return $KERNEL_FEATURE_BPF_GET_NETNS_COOKIE
    }
    if $field == "ktime" or $field == "timestamp" {
        return $KERNEL_FEATURE_BPF_KTIME_GET_NS
    }
    if $field in ["ktime_boot" "boot_ktime" "boot_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS
    }
    if $field in ["ktime_coarse" "coarse_ktime" "coarse_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS
    }
    if $field in ["ktime_tai" "tai_ktime" "tai_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS
    }
    if $field == "jiffies" {
        return $KERNEL_FEATURE_BPF_JIFFIES64
    }
    if $field in ["func_ip" "function_ip"] {
        return $KERNEL_FEATURE_BPF_GET_FUNC_IP
    }
    if $field in ["attach_cookie" "bpf_cookie"] {
        return $KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE
    }
    if $field in ["perf_counter" "perf_enabled" "perf_running"] {
        return $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE
    }
    if $field in ["xdp_buff_len" "xdp_buffer_len"] {
        return $KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN
    }
    if ($target_text | str starts-with "cgroup_sysctl:") {
        if $field in ["sysctl_name" "name" "sysctl_base_name" "base_name"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_NAME
        }
        if $field in ["sysctl_current_value" "current_value"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE
        }
        if $field in ["sysctl_new_value" "new_value"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE
        }
    }
    if $field == "arg_count" {
        return $KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT
    }
    if $field in ["kstack" "ustack"] {
        return $KERNEL_FEATURE_BPF_GET_STACKID
    }

    null
}

def iter-target-kernel-feature [target: string] {
    let matches = ($ITER_TARGET_KERNEL_FEATURES | where {|entry| $entry.target == $target })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def normalize-map-kind-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-map-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-helper-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-kfunc-name-token [token: string] {
    normalize-helper-name-token $token
}

def normalize-context-field-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | split row "."
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-context-path-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def context-field-access-is-assignment-lhs? [raw_access: string field: string] {
    let compact = ($raw_access | str trim | str replace --all " " "")
    if not ($compact | str contains "=") {
        return false
    }
    let parts = ($compact | split row "=")
    if ($parts | length) < 2 {
        return false
    }

    let rhs_after_first_equals = ($parts | skip 1 | first)
    if $rhs_after_first_equals == "" {
        return false
    }

    let lhs = ($parts | first)

    ($lhs == $field) or ($lhs | str starts-with $"($field).")
}

def line-assigns-context-field? [line: string context_names fields] {
    let trimmed = ($line | str trim)
    for context_name in $context_names {
        for field in $fields {
            let marker = $"$($context_name).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}

def line-assigns-record-context-field? [line: string aliases fields roots] {
    let trimmed = ($line | str trim)
    for alias in $aliases {
        let root = ($alias | get -o root | default "")
        if $root not-in $roots {
            continue
        }

        for field in $fields {
            let marker = $"$($alias.name).($alias.field).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}

def iter-btf-context-projection-root? [root: string] {
    $root in [
        "meta"
        "iter_meta"
        "task"
        "iter_task"
        "file"
        "iter_file"
        "vma"
        "iter_vma"
        "cgroup"
        "iter_cgroup"
        "map"
        "iter_map"
        "prog"
        "iter_prog"
        "link"
        "iter_link"
        "sk_common"
        "sock_common"
        "iter_sk_common"
        "udp_sk"
        "iter_udp_sk"
        "unix_sk"
        "iter_unix_sk"
        "rt"
        "route"
        "ipv6_route"
        "iter_ipv6_route"
        "cache"
        "kmem_cache"
        "iter_kmem_cache"
        "ksym"
        "iter_ksym"
        "netlink_sk"
        "iter_netlink_sk"
        "dmabuf"
        "iter_dmabuf"
        "sk"
        "sock"
        "socket"
        "iter_sock"
    ]
}

def iter-trusted-btf-context-projection-root? [root: string] {
    $root in [
        "meta"
        "iter_meta"
    ]
}

def context-projection-root? [root: string] {
    if (iter-btf-context-projection-root? $root) {
        return true
    }

    $root in [
        "sk"
        "sock"
        "socket"
        "migrating_sk"
        "migrating_socket"
        "arg"
        "arg0"
        "arg1"
        "arg2"
        "arg3"
        "arg4"
        "arg5"
        "retval"
        "task"
        "current_task"
        "cgroup"
        "current_cgroup"
        "state"
        "nf_state"
        "skb"
        "flow_keys"
    ]
}

def target-uses-btf-context-args? [target] {
    let target_text = ($target | default "")

    [
        "fentry:"
        "fentry.s:"
        "fexit:"
        "fexit.s:"
        "fmod_ret:"
        "fmod_ret.s:"
        "tp_btf:"
        "lsm:"
        "lsm.s:"
        "lsm_cgroup:"
        "struct_ops:"
    ] | any {|prefix| $target_text | str starts-with $prefix }
}

def target-uses-trusted-btf-context-args? [target] {
    let target_text = ($target | default "")

    [
        "fentry:"
        "fentry.s:"
        "fexit:"
        "fexit.s:"
        "fmod_ret:"
        "fmod_ret.s:"
        "lsm:"
        "lsm.s:"
        "lsm_cgroup:"
        "struct_ops:"
    ] | any {|prefix| $target_text | str starts-with $prefix }
}

def context-projection-parts [token: string] {
    let cleaned = (
        $token
        | str trim
        | split row " "
        | first
        | str replace --all ")" ""
        | str replace --all "(" ""
        | str replace --all "," ""
        | str replace --all "\"" ""
        | str replace --all "'" ""
        | str replace --all "}" ""
        | str replace --all "]" ""
        | str replace --all ";" ""
    )
    let parts = ($cleaned | split row ".")
    if ($parts | length) < 2 {
        return []
    }

    let root = ($parts | first)
    if not (context-projection-root? $root) {
        return []
    }

    $parts
}

def tracepoint-built-in-context-field? [field: string] {
    $field in [
        "pid"
        "tid"
        "tgid"
        "pid_tgid"
        "current_pid_tgid"
        "uid"
        "gid"
        "uid_gid"
        "current_uid_gid"
        "comm"
        "current_task"
        "current_cgroup"
        "cpu"
        "numa_node"
        "numa_node_id"
        "random"
        "prandom_u32"
        "ktime"
        "timestamp"
        "ktime_boot"
        "boot_ktime"
        "boot_time"
        "ktime_coarse"
        "coarse_ktime"
        "coarse_time"
        "ktime_tai"
        "tai_ktime"
        "tai_time"
        "jiffies"
        "func_ip"
        "function_ip"
        "attach_cookie"
        "bpf_cookie"
        "cgroup_id"
        "kstack"
        "ustack"
    ]
}

def bpf-sock-projection-context-field [member: string] {
    if $member == "bound_dev_if" {
        return "bound_dev_if"
    }
    if $member == "family" {
        return "family"
    }
    if $member == "type" or $member == "sock_type" {
        return "sock_type"
    }
    if $member == "protocol" or $member == "ip_protocol" {
        return "protocol"
    }
    if $member == "mark" {
        return "mark"
    }
    if $member == "priority" {
        return "priority"
    }
    if $member == "src_ip4" or $member == "local_ip4" {
        return "local_ip4"
    }
    if $member == "src_ip6" or $member == "local_ip6" {
        return "local_ip6"
    }
    if $member == "src_port" or $member == "local_port" {
        return "local_port"
    }
    if $member == "dst_ip4" or $member == "remote_ip4" {
        return "remote_ip4"
    }
    if $member == "dst_ip6" or $member == "remote_ip6" {
        return "remote_ip6"
    }
    if $member == "dst_port" or $member == "remote_port" {
        return "remote_port"
    }
    if $member == "state" {
        return "state"
    }
    if $member == "rx_queue_mapping" {
        return "rx_queue_mapping"
    }

    null
}

def context-projection-kernel-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }
    let root = ($parts | first)
    let member = ($parts | get 1)
    let target_text = ($target | default "")
    let socket_projection_root = (
        ($root in ["sk" "sock" "socket" "migrating_sk" "migrating_socket"])
        and not ($target_text | str starts-with "iter:")
    )

    if $socket_projection_root and $member == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_CGROUP_ID
    }
    if $socket_projection_root and $member == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID
    }
    if $socket_projection_root and ($member in ["tcp" "tcp_sock"]) {
        return $KERNEL_FEATURE_BPF_TCP_SOCK
    }
    if $socket_projection_root and ($member in ["full" "fullsock" "full_sock"]) {
        return $KERNEL_FEATURE_BPF_SK_FULLSOCK
    }
    if $socket_projection_root and $member == "listener" {
        return $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK
    }
    if $root == "flow_keys" {
        return (context-field-kernel-feature "flow_keys" $target)
    }
    if not $socket_projection_root {
        return null
    }

    let field = (bpf-sock-projection-context-field $member)
    if $field == null {
        return null
    }

    let feature = (context-field-kernel-feature $field $target)
    if $feature != null {
        return $feature
    }
    if $field == "rx_queue_mapping" {
        return $KERNEL_FEATURE_CTX_BPF_SOCK_RX_QUEUE_MAPPING
    }

    null
}

def trusted-btf-projection-kernel-read? [parts target] {
    if ($parts | length) < 2 {
        return false
    }

    let target_text = ($target | default "")
    let root = ($parts | first)
    let first_member = ($parts | get 1)

    if ($target_text | str starts-with "iter:") and (iter-trusted-btf-context-projection-root? $root) {
        return true
    }
    if $root in ["current_task" "current_cgroup"] {
        return true
    }
    if $root in ["task" "cgroup"] {
        if ($target_text | str starts-with "tracepoint:") {
            return false
        }
        if $root == "task" and $first_member == "pt_regs" {
            return false
        }
        return true
    }
    if ($target_text | str starts-with "netfilter:") and ($root in ["state" "nf_state" "skb"]) {
        return true
    }
    if (target-uses-trusted-btf-context-args? $target_text) {
        if $root == "arg" and ($parts | length) >= 3 {
            return true
        }
        if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
            return true
        }
    }

    false
}

def btf-context-arg-projection? [parts target] {
    if ($parts | length) < 2 {
        return false
    }

    let target_text = ($target | default "")
    if not (target-uses-btf-context-args? $target_text) {
        return false
    }

    let root = ($parts | first)
    if $root == "arg" and ($parts | length) >= 3 {
        return true
    }
    if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
        return true
    }

    false
}

def context-projection-kernel-read-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }

    let root = ($parts | first)
    let member = ($parts | get 1)
    let target_text = ($target | default "")
    if (bpf-sock-projection-context-field $member) != null {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    let helper_backed_socket_projection = (
        ($parts | length) >= 3
        and ($member in ["tcp" "tcp_sock" "full" "fullsock" "full_sock" "listener"])
    )
    if $helper_backed_socket_projection {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    if (
        ($target_text | str starts-with "iter:")
        and (iter-btf-context-projection-root? $root)
        and not (iter-trusted-btf-context-projection-root? $root)
    ) {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    if (trusted-btf-projection-kernel-read? $parts $target) {
        # Trusted kernel-BTF scalar projections lower as direct loads. Aggregate
        # projections that still need a helper should declare that explicitly.
        return null
    }
    if (btf-context-arg-projection? $parts $target) {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }

    null
}

def context-task-pt-regs-kernel-feature [raw_access: string] {
    let cleaned = (
        $raw_access
        | str trim
        | split row " "
        | first
        | str replace --all ")" ""
        | str replace --all "(" ""
        | str replace --all "," ""
        | str replace --all "\"" ""
        | str replace --all "'" ""
        | str replace --all "}" ""
        | str replace --all "]" ""
        | str replace --all ";" ""
    )
    let parts = ($cleaned | split row ".")
    if ($parts | length) < 3 {
        return null
    }

    let root = ($parts | first)
    if $root not-in ["task" "current_task"] {
        return null
    }
    if ($parts | get 1) != "pt_regs" {
        return null
    }
    if ($parts | get 2) not-in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"] {
        return null
    }

    $KERNEL_FEATURE_BPF_TASK_PT_REGS
}

def append-unique-name [names name: string] {
    if $name == "" or $name in $names {
        $names
    } else {
        $names | append $name
    }
}

def trim-simple-parentheses [text: string] {
    mut value = ($text | str trim)

    loop {
        if ($value | str length) < 2 {
            break
        }
        if not (($value | str starts-with "(") and ($value | str ends-with ")")) {
            break
        }

        $value = ($value | str substring 1..-2 | str trim)
    }

    $value
}

def split-pipeline-segments [raw: string] {
    let text = (trim-simple-parentheses ($raw | str trim))
    mut segments = []
    mut current = ""
    mut paren_depth = 0
    mut brace_depth = 0
    mut bracket_depth = 0
    mut in_single = false
    mut in_double = false

    for ch in ($text | split chars) {
        if ($ch == "'" and (not $in_double)) {
            $in_single = not $in_single
            $current = $"($current)($ch)"
            continue
        }
        if ($ch == '"' and (not $in_single)) {
            $in_double = not $in_double
            $current = $"($current)($ch)"
            continue
        }

        if (
            $ch == "|"
            and (not $in_single)
            and (not $in_double)
            and $paren_depth == 0
            and $brace_depth == 0
            and $bracket_depth == 0
        ) {
            $segments = ($segments | append ($current | str trim))
            $current = ""
            continue
        }

        if (not $in_single) and (not $in_double) {
            if $ch == "(" {
                $paren_depth = $paren_depth + 1
            } else if $ch == ")" {
                if $paren_depth > 0 {
                    $paren_depth = $paren_depth - 1
                }
            } else if $ch == "{" {
                $brace_depth = $brace_depth + 1
            } else if $ch == "}" {
                if $brace_depth > 0 {
                    $brace_depth = $brace_depth - 1
                }
            } else if $ch == "[" {
                $bracket_depth = $bracket_depth + 1
            } else if $ch == "]" {
                if $bracket_depth > 0 {
                    $bracket_depth = $bracket_depth - 1
                }
            }
        }

        $current = $"($current)($ch)"
    }

    $segments | append ($current | str trim)
}

def declaration-binding-name [raw_name: string] {
    $raw_name
    | str trim
    | split row ":"
    | first
    | str trim
    | split row " "
    | first
    | str trim
}

def declaration-assignment-from-body [body: string] {
    let assignment_parts = ($body | split row "=")
    if ($assignment_parts | length) < 2 {
        return null
    }

    let name = (declaration-binding-name ($assignment_parts | first))
    if $name == "" {
        return null
    }

    {
        name: $name
        rhs: ($assignment_parts | skip 1 | str join "=" | str trim)
    }
}

def declaration-assignments [line: string] {
    let trimmed = ($line | str trim)
    mut assignments = []

    for command in ["let" "mut"] {
        for tail in (command-invocation-tails $trimmed $command) {
            let assignment = (declaration-assignment-from-body ($tail | str trim))
            if $assignment != null {
                $assignments = ($assignments | append $assignment)
            }
        }
    }

    $assignments
}

def declaration-assignment [line: string] {
    declaration-assignments $line | first
}

def declaration-rhs-token [assignment] {
    trim-simple-parentheses (($assignment.rhs | split row ";" | first) | str trim)
}

def two-token-invocation [raw: string] {
    let tokens = (
        $raw
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if ($tokens | length) < 2 {
        return null
    }

    {
        callee: ($tokens | get 0)
        arg: (trim-simple-parentheses ($tokens | skip 1 | str join " "))
    }
}

def context-variable-binding [line: string context_names identity_wrappers] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        for context_name in $context_names {
            if $rhs == $"$($context_name)" {
                return $assignment.name
            }
        }

        let invocation = (two-token-invocation $rhs)
        if $invocation != null {
            if $invocation.callee in $identity_wrappers {
                for context_name in $context_names {
                    if $invocation.arg == $"$($context_name)" {
                        return $assignment.name
                    }
                }
            }
        }
    }

    null
}

def source-may-bind-derived-context-variable? [source: string] {
    (
        ($source | str contains "def ")
        or ($source | str contains " get ")
        or ($source | str contains "| get")
        or (($source | str contains "= $") and ($source | str contains "."))
        or (($source | str contains "= ($") and ($source | str contains "."))
    )
}

def program-context-variable-names [source: string] {
    mut names = ["ctx"]
    mut found_closure = false
    let identity_wrappers = (identity-wrapper-definitions $source)

    for line in ($source | lines) {
        if $found_closure {
            continue
        }

        let parts = ($line | split row "{|")
        if ($parts | length) <= 1 {
            continue
        }

        let raw_closure = ($parts | skip 1 | first)
        let closure_parts = ($raw_closure | split row "|")
        if ($closure_parts | length) == 0 {
            continue
        }

        let raw_params = ($closure_parts | first)
        for raw_param in ($raw_params | split row ",") {
            let name = (
                $raw_param
                | str trim
                | split row ":"
                | first
                | str trim
                | split row " "
                | first
                | str trim
            )
            $names = (append-unique-name $names $name)
        }
        $found_closure = true
    }

    for line in ($source | lines) {
        let binding = (context-variable-binding $line $names $identity_wrappers)
        if $binding != null {
            $names = (append-unique-name $names $binding)
        }
    }

    if (source-may-bind-derived-context-variable? $source) {
        for alias in (program-bound-context-root-aliases $source $names) {
            if (($alias | get -o root | default "") == "") {
                $names = (append-unique-name $names $alias.name)
            }
        }
    }

    $names
}

def context-root-from-wrapper-invocation [invocation context_names bound_aliases identity_wrappers root_wrapper_defs] {
    for wrapper in ($root_wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
        let root = (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
        if $root == null {
            continue
        }

        return (combine-context-roots $root ($wrapper | get -o root | default ""))
    }

    null
}

def context-root-from-multi-param-wrapper-invocation [raw_value: string context_names bound_aliases identity_wrappers wrapper_defs] {
    let trimmed = (trim-simple-parentheses ($raw_value | str trim))
    let callee = (
        $trimmed
        | split row " "
        | first
        | str trim
    )
    if $callee == "" {
        return null
    }

    let tail = (
        $trimmed
        | str substring ($callee | str length)..
        | str trim
    )
    let args = (command-tail-positional-args $tail)
    for wrapper in ($wrapper_defs | where {|wrapper| $wrapper.name == $callee }) {
        let arg = ($args | get -o $wrapper.param_index)
        if $arg == null {
            continue
        }

        let root = (context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers)
        if $root == null {
            continue
        }

        return (combine-context-roots $root ($wrapper | get -o root | default ""))
    }

    null
}

def context-root-binding [line: string context_names bound_aliases identity_wrappers root_wrapper_defs multi_param_root_wrapper_defs] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let direct_root = (context-root-from-value-token $rhs $context_names $bound_aliases)
        if $direct_root != null and $direct_root != "" {
            return { name: $assignment.name root: $direct_root }
        }

        let get_root = (context-root-from-get-pipeline $rhs $context_names $bound_aliases)
        if $get_root != null and $get_root != "" {
            return { name: $assignment.name root: $get_root }
        }

        let invocation = (two-token-invocation $rhs)
        if $invocation != null {
            if $invocation.callee in $identity_wrappers {
                let root_path = (
                    context-root-from-record-value-token
                        $invocation.arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
                if $root_path != null and $root_path != "" {
                    return { name: $assignment.name root: $root_path }
                }
            }

            let wrapper_root = (
                context-root-from-wrapper-invocation
                    $invocation
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $wrapper_root != null {
                return { name: $assignment.name root: $wrapper_root }
            }
        }

        let multi_param_wrapper_root = (
            context-root-from-multi-param-wrapper-invocation
                $rhs
                $context_names
                $bound_aliases
                $identity_wrappers
                $multi_param_root_wrapper_defs
        )
        if $multi_param_wrapper_root != null {
            return { name: $assignment.name root: $multi_param_wrapper_root }
        }

        for context_name in $context_names {
            let prefix = $"$($context_name)."
            if not ($rhs | str starts-with $prefix) {
                continue
            }

            let root_path = (normalize-context-path-token ($rhs | str substring ($prefix | str length)..))
            let root = ($root_path | split row "." | first)
            if (context-projection-root? $root) {
                return { name: $assignment.name root: $root_path }
            }
        }
    }

    null
}

def context-root-record-extraction-binding [line: string record_aliases record_wrapper_defs context_names bound_aliases identity_wrappers root_wrapper_defs] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)

        for parsed in (
            $rhs
            | parse --regex '^\$(?P<record>[A-Za-z_][A-Za-z0-9_-]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_-]*)$'
        ) {
            for alias in (
                $record_aliases
                | where {|alias| $alias.name == $parsed.record and $alias.field == $parsed.field }
            ) {
                return {
                    name: $assignment.name
                    root: ($alias | get -o root | default "")
                }
            }
        }

        let segments = (split-pipeline-segments $rhs)
        if ($segments | length) < 2 {
            continue
        }
        let input = (($segments | first) | str trim)
        mut roots = []
        mut prefix_segments = []

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                if ($roots | is-empty) {
                    $prefix_segments = ($prefix_segments | append ($segment | str trim))
                }
                continue
            }

            mut root = (
                context-root-from-record-get
                    $input
                    $parsed.field
                    $record_aliases
                    $record_wrapper_defs
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $root == null {
                $root = (
                    context-root-from-record-pipeline-get
                        $input
                        $prefix_segments
                        $parsed.field
                        $record_aliases
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
            }
            if $root == null {
                continue
            }

            $roots = ($roots | append $root)
        }

        if ($roots | length) == 1 {
            return {
                name: $assignment.name
                root: ($roots | first)
            }
        }
    }

    null
}

def context-root-from-record-get [input: string get_field: string record_aliases record_wrapper_defs context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let field_name = (normalize-context-path-token $get_field)
    if $field_name == "" {
        return null
    }
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let variable_input = (
        $normalized_input
        | str replace --all "(" ""
        | str replace --all ")" ""
        | str trim
    )

    for parsed in (
        $variable_input
        | parse --regex '^\$(?P<record>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in (
            $record_aliases
            | where {|alias| $alias.name == $parsed.record and $alias.field == $field_name }
        ) {
            return ($alias | get -o root | default "")
        }
    }

    let invocation = (two-token-invocation $normalized_input)
    if $invocation != null {
        for wrapper in (
            $record_wrapper_defs
            | where {|wrapper| $wrapper.name == $invocation.callee and $wrapper.field == $field_name }
        ) {
            let root = (
                context-root-from-record-wrapper-invocation
                    $invocation
                    $wrapper
                    $context_names
                    $bound_aliases
                    $identity_wrappers
            )
            if $root == null {
                continue
            }
            return (combine-context-roots $root ($wrapper | get -o root | default ""))
        }
    }

    for field in (
        record-literal-context-fields
            $normalized_input
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
    ) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    for field in (record-literal-spread-context-fields $normalized_input $record_aliases) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    null
}

def context-root-from-record-pipeline-get [input: string prefix_segments get_field: string record_aliases context_names bound_aliases identity_wrappers root_wrapper_defs] {
    if ($prefix_segments | is-empty) {
        return null
    }

    let raw = (
        [$input]
        | append $prefix_segments
        | str join " | "
    )
    let field_name = (normalize-context-path-token $get_field)
    for field in (
        record-pipeline-flow-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $record_aliases
    ) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    null
}

def program-bound-context-root-aliases-base [source: string context_names] {
    mut aliases = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let multi_param_root_wrapper_defs = (multi-param-context-root-wrapper-definitions $source)

    for line in ($source | lines) {
        let binding = (
            context-root-binding
                $line
                $context_names
                $aliases
                $identity_wrappers
                $root_wrapper_defs
                $multi_param_root_wrapper_defs
        )
        if $binding == null {
            continue
        }

        let existing = ($aliases | where {|alias| $alias.name == $binding.name })
        if ($existing | is-empty) {
            $aliases = ($aliases | append $binding)
        } else {
            $aliases = (
                $aliases
                | each {|alias|
                    if $alias.name == $binding.name { $binding } else { $alias }
                }
            )
        }
    }

    $aliases
}

def program-bound-context-root-aliases [source: string context_names] {
    mut aliases = (program-bound-context-root-aliases-base $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let record_aliases = (program-record-context-aliases $source $context_names)
    let record_wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            let binding = (
                context-root-record-extraction-binding
                    $line
                    $record_aliases
                    $record_wrapper_defs
                    $context_names
                    $aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $binding == null {
                continue
            }

            let existing = ($aliases | where {|alias| $alias.name == $binding.name })
            if ($existing | is-empty) {
                $aliases = ($aliases | append $binding)
                $changed = true
            } else {
                let current = ($existing | first)
                if (($current | get -o root | default "") != ($binding | get -o root | default "")) {
                    $aliases = (
                        $aliases
                        | each {|alias|
                            if $alias.name == $binding.name { $binding } else { $alias }
                        }
                    )
                    $changed = true
                }
            }
        }
    }

    $aliases
}

def context-root-from-record-value-token [raw_value: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let direct_root = (context-root-from-value-token $raw_value $context_names $bound_aliases)
    if $direct_root != null {
        return $direct_root
    }

    let get_root = (context-root-from-get-pipeline $raw_value $context_names $bound_aliases)
    if $get_root != null {
        return $get_root
    }

    let invocation = (two-token-invocation (trim-simple-parentheses ($raw_value | str trim)))
    if $invocation != null and $invocation.callee in $identity_wrappers {
        let root = (context-root-from-get-pipeline $invocation.arg $context_names $bound_aliases)
        if $root != null {
            return $root
        }

        return (context-root-from-value-token $invocation.arg $context_names $bound_aliases)
    }
    if $invocation != null {
        return (
            context-root-from-wrapper-invocation
                $invocation
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
    }

    null
}

def record-literal-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    let inner = ($trimmed | str substring 1..-2)
    mut fields = []
    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?|\(?[A-Za-z_][A-Za-z0-9_-]*\s+\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?\)?)'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\([^)]*\|\s*get\s+[^)]*\))'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\(?[A-Za-z_][A-Za-z0-9_-]*\s+\([^)]*\|\s*get\s+[^)]*\)\)?)'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    $fields
}

def record-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let order = (record-literal-field-names $rhs)
        for field in (
            record-literal-context-fields
                $rhs
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: $field.root
                order: $order
            })
        }
    }

    $bindings
}

def record-wrapper-definitions [source: string] {
    mut wrappers = []

    for line in ($source | lines) {
        for parsed in (
            $line
            | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*\{\s*(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\s*\}\s*$'
        ) {
            if $parsed.param != $parsed.value {
                continue
            }
            if (
                $wrappers
                | any {|wrapper| $wrapper.name == $parsed.name and $wrapper.field == $parsed.field }
            ) {
                continue
            }
            $wrappers = ($wrappers | append {
                name: $parsed.name
                field: $parsed.field
            })
        }
    }

    $wrappers
}

def context-root-from-record-wrapper-invocation [invocation wrapper context_names bound_aliases identity_wrappers] {
    let param_index = ($wrapper | get -o param_index)
    if $param_index == null {
        return (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
    }

    let args = (command-tail-positional-args $invocation.arg)
    let arg = ($args | get -o $param_index)
    if $arg == null {
        return null
    }

    context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers
}

def context-root-from-value-token [raw_value: string context_names bound_aliases] {
    let field_value = (trim-simple-parentheses ($raw_value | str trim))
    for context_name in $context_names {
        let context_token = (["$" $context_name] | str join "")
        if $field_value == $context_token {
            return ""
        }

        let context_prefix = $"($context_token)."
        if not ($field_value | str starts-with $context_prefix) {
            continue
        }

        let root_path = (
            normalize-context-path-token (
                $field_value | str substring ($context_prefix | str length)..
            )
        )
        let root = ($root_path | split row "." | first)
        if (context-projection-root? $root) {
            return $root_path
        }
    }

    for alias in $bound_aliases {
        let alias_token = (["$" $alias.name] | str join "")
        if $field_value == $alias_token {
            return $alias.root
        }

        let alias_prefix = $"($alias_token)."
        if not ($field_value | str starts-with $alias_prefix) {
            continue
        }

        let tail = (
            normalize-context-path-token (
                $field_value | str substring ($alias_prefix | str length)..
            )
        )
        return $"($alias.root).($tail)"
    }

    null
}

def context-root-from-argument-token [raw_value: string context_names bound_aliases identity_wrappers] {
    mut root = (context-root-from-get-pipeline $raw_value $context_names $bound_aliases)
    if $root == null {
        $root = (context-root-from-value-token $raw_value $context_names $bound_aliases)
    }
    if $root == null {
        let invocation = (two-token-invocation (trim-simple-parentheses ($raw_value | str trim)))
        if $invocation != null and $invocation.callee in $identity_wrappers {
            $root = (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
        }
    }

    $root
}

def combine-context-roots [base: string wrapper: string] {
    if $wrapper == "" {
        return $base
    }
    if $base == "" {
        return $wrapper
    }

    $"($base).($wrapper)"
}

def context-root-from-get-pipeline [raw: string context_names bound_aliases] {
    let trimmed = (trim-simple-parentheses ($raw | str trim))
    if (not ($trimmed | str contains "get")) or (not ($trimmed | str contains "|")) {
        return null
    }

    let segments = (split-pipeline-segments $trimmed)
    if ($segments | length) < 2 {
        return null
    }

    mut root = (
        context-root-from-value-token
            (($segments | first) | str trim)
            $context_names
            $bound_aliases
    )
    if $root == null {
        return null
    }

    mut saw_get = false
    for segment in ($segments | skip 1) {
        let parsed = (get-command-field-tail $segment)
        if $parsed == null {
            return null
        }

        let field_path = (normalize-context-path-token $parsed.field)
        if $field_path == "" {
            return null
        }
        $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
        $saw_get = true

        let tail_path = (get-segment-cell-path-tail $parsed.tail)
        if $tail_path != "" {
            $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
        }
    }

    if $saw_get { $root } else { null }
}

def record-wrapper-context-bindings [line: string context_names bound_aliases identity_wrappers wrapper_defs] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let invocation = (two-token-invocation $rhs)
        if $invocation == null {
            continue
        }

        for wrapper in ($wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
            let root = (
                context-root-from-record-wrapper-invocation
                    $invocation
                    $wrapper
                    $context_names
                    $bound_aliases
                    $identity_wrappers
            )
            if $root == null {
                continue
            }
            let wrapper_root = ($wrapper | get -o root | default "")
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $wrapper.field
                root: (combine-context-roots $root $wrapper_root)
            })
        }
    }

    $bindings
}

def record-upsert-context-bindings [line: string context_names bound_aliases] {
    mut bindings = []

    for parsed in (
        $line
        | parse --regex '^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?P<value>\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?)'
    ) {
        let root = (context-root-from-value-token $parsed.value $context_names $bound_aliases)
        if $root != null {
            $bindings = ($bindings | append {
                name: $parsed.name
                field: $parsed.field
                root: $root
            })
        }
    }

    $bindings
}

def record-command-field-value [tail: string] {
    let parsed = (
        $tail
        | str trim
        | parse --regex '^(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s+(?P<value>.+)$'
    )
    if ($parsed | is-empty) {
        return null
    }

    let result = ($parsed | first)
    {
        field: ($result.field | str trim)
        value: ($result.value | str trim)
    }
}

def record-default-field-value [tail: string] {
    let parts = (
        $tail
        | str trim
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if ($parts | length) < 2 {
        return null
    }

    let field = (normalize-context-path-token ($parts | last))
    let value = (
        $parts
        | first (($parts | length) - 1)
        | str join " "
        | str trim
    )
    if $field == "" or $value == "" {
        return null
    }

    {
        field: $field
        value: $value
    }
}

def record-pipeline-input-token [raw: string] {
    let input = (
        split-pipeline-segments $raw
        | first
        | str trim
    )
    trim-simple-parentheses $input
}

def unique-record-context-fields [fields] {
    mut unique = []

    for field in $fields {
        if (
            $unique
            | any {|existing|
                (
                    $existing.field == $field.field
                    and (($existing | get -o root | default "") == ($field | get -o root | default ""))
                )
            }
        ) {
            continue
        }
        $unique = ($unique | append {
            field: $field.field
            root: ($field | get -o root | default "")
        })
    }

    $unique
}

def record-literal-field-names [raw: string] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:'
    ) {
        if $parsed.field not-in $names {
            $names = ($names | append $parsed.field)
        }
    }

    $names
}

def record-literal-spread-field-names [raw: string aliases] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '\.\.\.\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            if $alias.field not-in $names {
                $names = ($names | append $alias.field)
            }
        }
    }

    $names
}

def record-literal-null-field-names [raw: string] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*null(?:\s|,|$)'
    ) {
        if $parsed.field not-in $names {
            $names = ($names | append $parsed.field)
        }
    }

    $names
}

def record-field-name-list [raw: string] {
    mut names = []

    for token in (
        $raw
        | str trim
        | split row " "
        | each {|part| normalize-context-path-token $part }
        | where {|part| $part != "" }
    ) {
        let name = ($token | split row "." | first)
        if $name != "" and $name not-in $names {
            $names = ($names | append $name)
        }
    }

    $names
}

def record-literal-argument [raw: string] {
    let parsed = (
        $raw
        | str trim
        | parse --regex '^(?P<record>\{.*\})\s*\)*$'
    )
    if ($parsed | is-empty) {
        return null
    }

    ($parsed | first).record
}

def record-pipeline-input-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let input = (record-pipeline-input-token $raw)
    mut fields = (
        record-literal-context-fields
            $input
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
    )
    $fields = (
        $fields
        | append (record-literal-spread-context-fields $input $aliases)
    )

    for parsed in (
        $input
        | parse --regex '^\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            $fields = ($fields | append {
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-input-field-order [raw: string aliases] {
    let input = (record-pipeline-input-token $raw)
    let literal_order = (record-literal-field-names $input)
    let spread_order = (record-literal-spread-field-names $input $aliases)

    if ($spread_order | is-empty) and not ($literal_order | is-empty) {
        return $literal_order
    }
    if ($literal_order | is-empty) and not ($spread_order | is-empty) {
        return $spread_order
    }

    for parsed in (
        $input
        | parse --regex '^\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            let order = ($alias | get -o order | default [])
            if not ($order | is-empty) {
                return $order
            }
        }
    }

    null
}

def record-pipeline-input-null-fields [raw: string] {
    let input = (record-pipeline-input-token $raw)
    let literal_nulls = (record-literal-null-field-names $input)
    if not ($literal_nulls | is-empty) {
        return $literal_nulls
    }

    []
}

def remove-record-context-field [fields field_name: string] {
    $fields | where {|field| $field.field != $field_name }
}

def remove-field-name [fields field_name: string] {
    $fields | where {|field| $field != $field_name }
}

def append-field-name [fields field_name: string] {
    if $field_name in $fields {
        return $fields
    }

    $fields | append $field_name
}

def value-token-null? [raw: string] {
    (normalize-context-path-token (trim-simple-parentheses ($raw | str trim))) == "null"
}

def append-record-context-field [fields field_name: string root: string] {
    unique-record-context-fields (
        $fields
        | append {
            field: $field_name
            root: $root
        }
    )
}

def replace-record-context-field [fields field_name: string root] {
    mut next = (remove-record-context-field $fields $field_name)
    if $root != null {
        $next = (append-record-context-field $next $field_name $root)
    }

    $next
}

def has-record-context-field? [fields field_name: string] {
    $fields | any {|field| $field.field == $field_name }
}

def record-field-index [order field_name: string] {
    if $order == null {
        return null
    }

    for entry in ($order | enumerate) {
        if $entry.item == $field_name {
            return $entry.index
        }
    }

    null
}

def record-field-name-at-index [names index: int fallback: string] {
    if $index < ($names | length) {
        return ($names | get $index)
    }

    $fallback
}

def rename-record-context-fields [fields order rename_names] {
    if $order == null {
        return $fields
    }

    mut renamed = []
    for field in $fields {
        let index = (record-field-index $order $field.field)
        let next_name = if $index == null {
            $field.field
        } else {
            record-field-name-at-index $rename_names $index $field.field
        }
        $renamed = ($renamed | append {
            field: $next_name
            root: ($field | get -o root | default "")
        })
    }

    unique-record-context-fields $renamed
}

def rename-record-field-order [order rename_names] {
    if $order == null {
        return null
    }

    mut renamed = []
    for field in ($order | enumerate) {
        let next_name = (record-field-name-at-index $rename_names $field.index $field.item)
        $renamed = ($renamed | append $next_name)
    }

    $renamed
}

def merge-record-field-order [order merge_fields] {
    if $order == null {
        return null
    }

    mut next = $order
    for field in $merge_fields {
        if $field not-in $next {
            $next = ($next | append $field)
        }
    }

    $next
}

def upsert-record-field-order [order field_name: string] {
    if $order == null {
        return null
    }
    if $field_name in $order {
        return $order
    }

    $order | append $field_name
}

def record-pipeline-flow-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let parts = (split-pipeline-segments $raw)
    if ($parts | length) <= 1 {
        return []
    }

    mut fields = (
        record-pipeline-input-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
    mut field_order = (record-pipeline-input-field-order $raw $aliases)
    mut null_fields = (record-pipeline-input-null-fields $raw)

    for segment in ($parts | skip 1) {
        let trimmed = ($segment | str trim)

        for command in [insert update upsert] {
            if not (($trimmed == $command) or ($trimmed | str starts-with $"($command) ")) {
                continue
            }

            let tail = ($trimmed | str substring ($command | str length).. | str trim)
            let field_value = (record-command-field-value $tail)
            if $field_value == null {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }

        if ($trimmed | str starts-with "merge ") {
            let merge_arg = (record-literal-argument ($trimmed | str substring 5.. | str trim))
            if $merge_arg == null {
                continue
            }

            let merge_fields = (record-literal-field-names $merge_arg)
            for field in $merge_fields {
                $fields = (remove-record-context-field $fields $field)
                $null_fields = (remove-field-name $null_fields $field)
            }
            $fields = (unique-record-context-fields (
                $fields
                | append (
                    record-literal-context-fields
                        $merge_arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
            ))
            for field in (record-literal-null-field-names $merge_arg) {
                $null_fields = (append-field-name $null_fields $field)
            }
            $field_order = (merge-record-field-order $field_order $merge_fields)
        }

        if ($trimmed | str starts-with "select ") {
            let selected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field in $selected })
            $field_order = $selected
            $null_fields = ($null_fields | where {|field| $field in $selected })
        }

        if ($trimmed | str starts-with "reject ") {
            let rejected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field not-in $rejected })
            $null_fields = ($null_fields | where {|field| $field not-in $rejected })
            if $field_order != null {
                $field_order = ($field_order | where {|field| $field not-in $rejected })
            }
        }

        if ($trimmed | str starts-with "rename ") {
            let rename_names = (record-field-name-list ($trimmed | str substring 6..))
            $fields = (rename-record-context-fields $fields $field_order $rename_names)
            $null_fields = (rename-record-field-order $null_fields $rename_names)
            $field_order = (rename-record-field-order $field_order $rename_names)
        }

        if ($trimmed | str starts-with "default ") {
            let field_value = (record-default-field-value ($trimmed | str substring 7..))
            if $field_value == null {
                continue
            }

            let field_exists = ($field_order != null and $field_value.field in $field_order)
            let can_fill_field = (
                not (has-record-context-field? $fields $field_value.field)
                and (not $field_exists or $field_value.field in $null_fields)
            )
            if not $can_fill_field {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-flow-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    mut bindings = []

    for assignment in (declaration-assignments $line) {
        for field in (
            record-pipeline-flow-context-fields
                (declaration-rhs-token $assignment)
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
                $aliases
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}

def record-literal-spread-context-fields [raw: string aliases] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut fields = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '\.\.\.\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            $fields = ($fields | append {
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    $fields
}

def record-spread-context-bindings [line: string aliases] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        for field in (record-literal-spread-context-fields (declaration-rhs-token $assignment) $aliases) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}

def identity-wrapper-definitions [source: string] {
    mut identities = []
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            for parsed in (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*\(?\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\)?\s*\}\s*$'
            ) {
                if $parsed.param != $parsed.value {
                    continue
                }
                if $parsed.name not-in $identities {
                    $identities = ($identities | append $parsed.name)
                    $changed = true
                }
            }

            for parsed in (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*(?P<callee>[A-Za-z_][A-Za-z0-9_-]*)\s+\(?\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\)?\s*\}\s*$'
            ) {
                if $parsed.param != $parsed.value {
                    continue
                }
                if $parsed.callee not-in $identities {
                    continue
                }
                if $parsed.name not-in $identities {
                    $identities = ($identities | append $parsed.name)
                    $changed = true
                }
            }
        }
    }

    $identities
}

def function-record-context-aliases [body param: string identity_wrappers root_wrapper_defs root_aliases] {
    mut aliases = []

    for line in $body {
        let bindings = (
            (record-context-bindings $line [$param] $root_aliases $identity_wrappers $root_wrapper_defs)
            | append (record-upsert-context-bindings $line [$param] $root_aliases)
            | append (record-pipeline-flow-context-bindings $line [$param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
            | append (record-spread-context-bindings $line $aliases)
        )
        for binding in $bindings {
            if (
                $aliases
                | any {|alias|
                    (
                        $alias.name == $binding.name
                        and $alias.field == $binding.field
                        and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                    )
                }
            ) {
                continue
            }
            $aliases = ($aliases | append $binding)
        }
    }

    $aliases
}

def context-root-from-returned-record-get-pipeline [returned: string record_aliases param: string root_aliases identity_wrappers root_wrapper_defs] {
    let segments = (split-pipeline-segments $returned)
    if ($segments | length) < 2 {
        return null
    }

    let input = (($segments | first) | str trim)
    mut roots = []
    mut prefix_segments = []

    for segment in ($segments | skip 1) {
        let parsed = (get-command-field-tail $segment)
        if $parsed == null {
            if ($roots | is-empty) {
                $prefix_segments = ($prefix_segments | append ($segment | str trim))
            }
            continue
        }

        mut root = (
            context-root-from-record-get
                $input
                $parsed.field
                $record_aliases
                []
                [$param]
                $root_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root == null {
            $root = (
                context-root-from-record-pipeline-get
                    $input
                    $prefix_segments
                    $parsed.field
                    $record_aliases
                    [$param]
                    $root_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
        }
        if $root == null {
            continue
        }

        $roots = ($roots | append $root)
    }

    if ($roots | length) == 1 {
        return ($roots | first)
    }

    null
}

def function-return-context-root [function identity_wrappers root_wrapper_defs] {
    let param = $function.param
    let aliases = (
        function-context-root-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
    )
    let record_aliases = (
        function-record-context-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
    let return_lines = (
        $function.body
        | each {|line| $line | str trim }
        | where {|line|
            (
                $line != ""
                and not ($line | str starts-with "#")
                and not ($line | str contains "=")
            )
        }
    )
    if ($return_lines | is-empty) {
        return null
    }

    let returned = ($return_lines | last)
    if ($returned | str contains "|") {
        let root = (context-root-from-get-pipeline $returned [$param] $aliases)
        if $root != null {
            return $root
        }

        let record_root = (
            context-root-from-returned-record-get-pipeline
                $returned
                $record_aliases
                $param
                $aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $record_root != null {
            return $record_root
        }

        return null
    }

    mut root = (context-root-from-value-token $returned [$param] $aliases)
    if $root != null {
        return $root
    }

    let invocation = (two-token-invocation $returned)
    if $invocation == null {
        return null
    }

    if $invocation.callee in $identity_wrappers {
        $root = (context-root-from-get-pipeline $invocation.arg [$param] $aliases)
        if $root != null {
            return $root
        }

        $root = (context-root-from-value-token $invocation.arg [$param] $aliases)
        if $root != null {
            return $root
        }
    }

    context-root-from-wrapper-invocation $invocation [$param] $aliases $identity_wrappers $root_wrapper_defs
}

def context-root-wrapper-definitions [source: string] {
    let identity_wrappers = (identity-wrapper-definitions $source)
    mut wrappers = []
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for function in (one-param-user-functions $source) {
            let root = (function-return-context-root $function $identity_wrappers $wrappers)
            if $root == null {
                continue
            }
            if (
                $wrappers
                | any {|wrapper| $wrapper.name == $function.name and (($wrapper | get -o root | default "") == $root) }
            ) {
                continue
            }

            $wrappers = ($wrappers | append {
                name: $function.name
                root: $root
            })
            $changed = true
        }
    }

    $wrappers
}

def one-param-user-functions [source: string] {
    mut functions = []
    mut in_function = false
    mut current_name = ""
    mut current_param = ""
    mut current_body = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)

        if not $in_function {
            let one_line = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*(?P<body>.*?)\s*\}\s*$'
            )
            if not ($one_line | is-empty) {
                let parsed = ($one_line | first)
                $functions = ($functions | append {
                    name: $parsed.name
                    param: $parsed.param
                    body: [$parsed.body]
                })
                continue
            }

            let header = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*$'
            )
            if not ($header | is-empty) {
                let parsed = ($header | first)
                $in_function = true
                $current_name = $parsed.name
                $current_param = $parsed.param
                $current_body = []
            }
            continue
        }

        if $trimmed == "}" {
            $functions = ($functions | append {
                name: $current_name
                param: $current_param
                body: $current_body
            })
            $in_function = false
            $current_name = ""
            $current_param = ""
            $current_body = []
            continue
        }

        $current_body = ($current_body | append $line)
    }

    $functions
}

def record-context-wrapper-definitions [source: string] {
    mut wrappers = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let base_wrapper_defs = (record-wrapper-definitions $source)

    for function in (one-param-user-functions $source) {
        mut aliases = []
        mut returned_names = []
        let root_aliases = (
            function-context-root-aliases
                $function.body
                $function.param
                $identity_wrappers
                $root_wrapper_defs
        )

        for line in $function.body {
            let trimmed = ($line | str trim)
            let bindings = (
                (record-context-bindings $line [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-wrapper-context-bindings $line [$function.param] $root_aliases $identity_wrappers $base_wrapper_defs)
                | append (record-upsert-context-bindings $line [$function.param] $root_aliases)
                | append (record-pipeline-flow-context-bindings $line [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
                | append (record-spread-context-bindings $line $aliases)
            )
            for binding in $bindings {
                let existing = (
                    $aliases
                    | where {|alias|
                        (
                            $alias.name == $binding.name
                            and $alias.field == $binding.field
                            and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                        )
                    }
                )
                if ($existing | is-empty) {
                    $aliases = ($aliases | append $binding)
                }
            }

            for parsed in (
                $line
                | parse --regex '^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*$'
            ) {
                $returned_names = ($returned_names | append $parsed.name)
            }

            mut returned_fields = (
                (record-literal-context-fields $trimmed [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-literal-spread-context-fields $trimmed $aliases)
                | append (record-pipeline-flow-context-fields $trimmed [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
            )
            let invocation = (two-token-invocation $trimmed)
            if $invocation != null {
                for wrapper in ($base_wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
                    let root = (context-root-from-value-token $invocation.arg [$function.param] $root_aliases)
                    if $root == null {
                        continue
                    }
                    $returned_fields = ($returned_fields | append {
                        field: $wrapper.field
                        root: (combine-context-roots $root ($wrapper | get -o root | default ""))
                    })
                }
            }
            for field in $returned_fields {
                if (
                    $wrappers
                    | any {|wrapper|
                        (
                            $wrapper.name == $function.name
                            and $wrapper.field == $field.field
                            and (($wrapper | get -o root | default "") == ($field | get -o root | default ""))
                        )
                    }
                ) {
                    continue
                }
                $wrappers = ($wrappers | append {
                    name: $function.name
                    field: $field.field
                    root: ($field | get -o root | default "")
                })
            }
        }

        for alias in $aliases {
            if $alias.name not-in $returned_names {
                continue
            }
            if (
                $wrappers
                | any {|wrapper|
                    (
                        $wrapper.name == $function.name
                        and $wrapper.field == $alias.field
                        and (($wrapper | get -o root | default "") == ($alias | get -o root | default ""))
                    )
                }
            ) {
                continue
            }
            $wrappers = ($wrappers | append {
                name: $function.name
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    $wrappers
}

def upsert-context-root-alias [aliases name: string root: string] {
    if ($aliases | any {|alias| $alias.name == $name }) {
        $aliases | each {|alias|
            if $alias.name == $name {
                { name: $name root: $root }
            } else {
                $alias
            }
        }
    } else {
        $aliases | append { name: $name root: $root }
    }
}

def function-context-root-aliases [body param: string identity_wrappers root_wrapper_defs] {
    mut aliases = []

    for line in $body {
        for assignment in (declaration-assignments $line) {
            let rhs = (declaration-rhs-token $assignment)
            mut root = (context-root-from-argument-token $rhs [$param] $aliases $identity_wrappers)
            if $root == null {
                let invocation = (two-token-invocation $rhs)
                if $invocation != null {
                    $root = (
                        context-root-from-wrapper-invocation
                            $invocation
                            [$param]
                            $aliases
                            $identity_wrappers
                            $root_wrapper_defs
                    )
                }
            }

            if $root != null {
                $aliases = (upsert-context-root-alias $aliases $assignment.name $root)
            }
        }
    }

    $aliases
}

def append-function-context-field-access [accesses function_name: string raw_access: string] {
    let field = (normalize-context-field-token $raw_access)
    if $field == "" {
        return $accesses
    }
    if (
        $accesses
        | any {|access| $access.name == $function_name and $access.raw_access == $raw_access }
    ) {
        return $accesses
    }

    $accesses | append {
        name: $function_name
        raw_access: $raw_access
    }
}

def function-context-field-accesses [function identity_wrappers root_wrapper_defs] {
    mut accesses = []
    let param = $function.param
    let aliases = (
        function-context-root-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
    )
    let roots = ([{ name: $param root: "" }] | append $aliases)

    for line in $function.body {
        for root in $roots {
            let prefix = $"$($root.name)."
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $root.root == "" {
                    $raw_tail
                } else {
                    $"($root.root).($raw_tail)"
                }
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }
                $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
            }
        }

        for candidate in (record-get-candidate-lines $line) {
            let segments = (split-pipeline-segments ($candidate | str trim))
            if ($segments | length) < 2 {
                continue
            }

            mut input = (($segments | first) | str trim)
            if ($input | str contains "=") {
                $input = (($input | split row "=" | last) | str trim)
            }
            mut root = null

            for segment in ($segments | skip 1) {
                let parsed = (get-command-field-tail $segment)
                if $parsed == null {
                    continue
                }

                if $root == null {
                    $root = (context-root-from-get-input $input [$param] $aliases)
                    if $root == null {
                        continue
                    }
                }

                let field_path = (normalize-context-path-token $parsed.field)
                if $field_path != "" {
                    let raw_access = if $root == "" { $field_path } else { $"($root).($field_path)" }
                    $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
                    $root = $raw_access
                }

                let tail_path = (get-segment-cell-path-tail $parsed.tail)
                if $tail_path != "" {
                    let raw_access = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
                    $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
                    $root = $raw_access
                }
            }
        }
    }

    $accesses
}

def user-function-context-field-accesses [source: string] {
    mut accesses = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (one-param-user-functions $source) {
        $accesses = (
            $accesses
            | append (function-context-field-accesses $function $identity_wrappers $root_wrapper_defs)
        )
    }

    $accesses
}

def simple-function-param-names [raw_params: string] {
    let parts = (
        $raw_params
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if (
        $parts
        | any {|part|
            (
                ($part | str contains ":")
                or ($part | str starts-with "-")
                or ($part | str starts-with "...")
            )
        }
    ) {
        return []
    }

    $parts
    | each {|part|
        $part
        | str replace --all "," ""
        | str replace --all "?" ""
        | split row ":"
        | first
        | str trim
    }
    | where {|name| $name != "" and not ($name | str starts-with "-") }
}

def positional-user-functions [source: string] {
    mut functions = []
    mut in_function = false
    mut current_name = ""
    mut current_params = []
    mut current_body = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)

        if not $in_function {
            let one_line = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<params>[^\]]*)\s*\]\s*\{\s*(?P<body>.*?)\s*\}\s*$'
            )
            if not ($one_line | is-empty) {
                let parsed = ($one_line | first)
                let params = (simple-function-param-names $parsed.params)
                if not ($params | is-empty) {
                    $functions = ($functions | append {
                        name: $parsed.name
                        params: $params
                        body: [$parsed.body]
                    })
                }
                continue
            }

            let header = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<params>[^\]]*)\s*\]\s*\{\s*$'
            )
            if not ($header | is-empty) {
                let parsed = ($header | first)
                let params = (simple-function-param-names $parsed.params)
                if ($params | is-empty) {
                    continue
                }
                $in_function = true
                $current_name = $parsed.name
                $current_params = $params
                $current_body = []
            }
            continue
        }

        if $trimmed == "}" {
            $functions = ($functions | append {
                name: $current_name
                params: $current_params
                body: $current_body
            })
            $in_function = false
            $current_name = ""
            $current_params = []
            $current_body = []
            continue
        }

        $current_body = ($current_body | append $line)
    }

    $functions
}

def multi-param-context-root-wrapper-definitions [source: string] {
    mut wrappers = []

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        let return_lines = (
            $function.body
            | each {|line| $line | str trim }
            | where {|line|
                (
                    $line != ""
                    and not ($line | str starts-with "#")
                    and not ($line | str contains "=")
                )
            }
        )
        if ($return_lines | is-empty) {
            continue
        }

        let returned = ($return_lines | last)
        for param in ($function.params | enumerate) {
            mut root = (context-root-from-get-pipeline $returned [$param.item] [])
            if $root == null {
                $root = (context-root-from-value-token $returned [$param.item] [])
            }
            if $root == null {
                continue
            }
            let final_root = $root
            if (
                $wrappers
                | any {|wrapper|
                    (
                        $wrapper.name == $function.name
                        and $wrapper.param_index == $param.index
                        and (($wrapper | get -o root | default "") == $final_root)
                    )
                }
            ) {
                continue
            }

            $wrappers = ($wrappers | append {
                name: $function.name
                param_index: $param.index
                root: $final_root
            })
        }
    }

    $wrappers
}

def multi-param-record-wrapper-definitions [source: string] {
    mut wrappers = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        for line in $function.body {
            let trimmed = ($line | str trim)
            if $trimmed == "" or ($trimmed | str starts-with "#") {
                continue
            }

            for param in ($function.params | enumerate) {
                for field in (record-literal-context-fields $trimmed [$param.item] [] $identity_wrappers $root_wrapper_defs) {
                    if (
                        $wrappers
                        | any {|wrapper|
                            (
                                $wrapper.name == $function.name
                                and $wrapper.field == $field.field
                                and $wrapper.param_index == $param.index
                                and (($wrapper | get -o root | default "") == ($field | get -o root | default ""))
                            )
                        }
                    ) {
                        continue
                    }

                    $wrappers = ($wrappers | append {
                        name: $function.name
                        field: $field.field
                        param_index: $param.index
                        root: ($field | get -o root | default "")
                    })
                }
            }
        }
    }

    $wrappers
}

def command-tail-positional-args [raw_tail: string] {
    let text = ($raw_tail | str trim)
    if $text == "" {
        return []
    }

    mut args = []
    mut current = ""
    mut paren_depth = 0
    mut brace_depth = 0
    mut bracket_depth = 0
    mut in_single = false
    mut in_double = false

    for ch in ($text | split chars) {
        if ($ch == "'" and (not $in_double)) {
            $in_single = not $in_single
            $current = $"($current)($ch)"
            continue
        }
        if ($ch == '"' and (not $in_single)) {
            $in_double = not $in_double
            $current = $"($current)($ch)"
            continue
        }

        let at_top = (
            (not $in_single)
            and (not $in_double)
            and $paren_depth == 0
            and $brace_depth == 0
            and $bracket_depth == 0
        )
        if $at_top and $ch == ";" {
            break
        }
        if $at_top and ($ch == " " or $ch == "\t") {
            let arg = ($current | str trim)
            if $arg != "" {
                $args = ($args | append $arg)
            }
            $current = ""
            continue
        }

        if (not $in_single) and (not $in_double) {
            if $ch == "(" {
                $paren_depth = $paren_depth + 1
            } else if $ch == ")" and $paren_depth > 0 {
                $paren_depth = $paren_depth - 1
            } else if $ch == "{" {
                $brace_depth = $brace_depth + 1
            } else if $ch == "}" and $brace_depth > 0 {
                $brace_depth = $brace_depth - 1
            } else if $ch == "[" {
                $bracket_depth = $bracket_depth + 1
            } else if $ch == "]" and $bracket_depth > 0 {
                $bracket_depth = $bracket_depth - 1
            }
        }

        $current = $"($current)($ch)"
    }

    let arg = ($current | str trim)
    if $arg != "" {
        $args = ($args | append $arg)
    }

    $args
}

def multi-param-function-context-field-accesses [source: string] {
    mut accesses = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        for param in ($function.params | enumerate) {
            let aliases = (
                function-context-root-aliases
                    $function.body
                    $param.item
                    $identity_wrappers
                    $root_wrapper_defs
            )
            let roots = ([{ name: $param.item root: "" }] | append $aliases)
            for line in $function.body {
                for root_info in $roots {
                    let prefix = $"$($root_info.name)."
                    for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                        let root_path = ($root_info | get -o root | default "")
                        let raw_access = if $root_path == "" {
                            $raw_tail
                        } else {
                            $"($root_path).($raw_tail)"
                        }
                        let field = (normalize-context-field-token $raw_access)
                        if $field == "" {
                            continue
                        }
                        if (
                            $accesses
                            | any {|access|
                                (
                                    $access.name == $function.name
                                    and $access.param_index == $param.index
                                    and $access.raw_access == $raw_access
                                )
                            }
                        ) {
                            continue
                        }
                        $accesses = ($accesses | append {
                            name: $function.name
                            param_index: $param.index
                            raw_access: $raw_access
                        })
                    }
                }

                for candidate in (record-get-candidate-lines $line) {
                    let segments = (split-pipeline-segments ($candidate | str trim))
                    if ($segments | length) < 2 {
                        continue
                    }

                    mut input = (($segments | first) | str trim)
                    if ($input | str contains "=") {
                        $input = (($input | split row "=" | last) | str trim)
                    }
                    mut root = null

                    for segment in ($segments | skip 1) {
                        let parsed = (get-command-field-tail $segment)
                        if $parsed == null {
                            continue
                        }

                        if $root == null {
                            $root = (context-root-from-get-input $input [$param.item] $aliases)
                            if $root == null {
                                continue
                            }
                        }

                        let field_path = (normalize-context-path-token $parsed.field)
                        if $field_path != "" {
                            let raw_access = if $root == "" { $field_path } else { $"($root).($field_path)" }
                            if not (
                                $accesses
                                | any {|access|
                                    (
                                        $access.name == $function.name
                                        and $access.param_index == $param.index
                                        and $access.raw_access == $raw_access
                                    )
                                }
                            ) {
                                $accesses = ($accesses | append {
                                    name: $function.name
                                    param_index: $param.index
                                    raw_access: $raw_access
                                })
                            }
                            $root = $raw_access
                        }

                        let tail_path = (get-segment-cell-path-tail $parsed.tail)
                        if $tail_path != "" {
                            let raw_access = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
                            if not (
                                $accesses
                                | any {|access|
                                    (
                                        $access.name == $function.name
                                        and $access.param_index == $param.index
                                        and $access.raw_access == $raw_access
                                    )
                                }
                            ) {
                                $accesses = ($accesses | append {
                                    name: $function.name
                                    param_index: $param.index
                                    raw_access: $raw_access
                                })
                            }
                            $root = $raw_access
                        }
                    }
                }
            }
        }
    }

    $accesses
}

def multi-param-user-function-context-field-kernel-features [source: string target context_names] {
    if not ($source | str contains "def ") {
        return []
    }

    mut features = []
    let accesses = (multi-param-function-context-field-accesses $source)
    if ($accesses | is-empty) {
        return $features
    }

    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") or ($trimmed | str starts-with "def ") {
            continue
        }

        for access in $accesses {
            for raw_tail in (command-invocation-tails $trimmed $access.name) {
                let args = (command-tail-positional-args $raw_tail)
                let arg = ($args | get -o $access.param_index)
                if $arg == null {
                    continue
                }

                let root = (context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers)
                if $root == null {
                    continue
                }
                let raw_access = if $root == "" {
                    $access.raw_access
                } else {
                    $"($root).($access.raw_access)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def context-access-kernel-features [raw_access: string target] {
    mut features = []
    let field = (normalize-context-field-token $raw_access)
    if $field == "" {
        return $features
    }

    let feature = (context-field-kernel-feature $field $target)
    if $feature != null {
        $features = (append-missing-kernel-features $features [$feature])
    }
    let tracepoint_feature = (tracepoint-payload-field-kernel-feature $field $target)
    if $tracepoint_feature != null {
        $features = (append-missing-kernel-features $features [$tracepoint_feature])
    }
    if not (context-field-access-is-assignment-lhs? $raw_access $field) {
        let helper_feature = (context-field-helper-kernel-feature $field $target)
        if $helper_feature != null {
            $features = (append-missing-kernel-features $features [$helper_feature])
        }
    }
    let projection_feature = (context-projection-kernel-feature $raw_access $target)
    if $projection_feature != null {
        $features = (append-missing-kernel-features $features [$projection_feature])
    }
    let read_feature = (context-projection-kernel-read-feature $raw_access $target)
    if $read_feature != null {
        $features = (append-missing-kernel-features $features [$read_feature])
    }
    let task_pt_regs_feature = (context-task-pt-regs-kernel-feature $raw_access)
    if $task_pt_regs_feature != null {
        $features = (append-missing-kernel-features $features [$task_pt_regs_feature])
    }

    $features
}

def user-function-context-field-kernel-features [source: string target context_names] {
    if not ($source | str contains "def ") {
        return []
    }

    mut features = []
    let accesses = (user-function-context-field-accesses $source)
    if ($accesses | is-empty) {
        return $features
    }

    let bound_aliases = (program-bound-context-root-aliases $source $context_names)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") or ($trimmed | str starts-with "def ") {
            continue
        }

        for access in $accesses {
            for raw_tail in (command-invocation-tails $trimmed $access.name) {
                let arg = (normalize-context-path-token $raw_tail)
                let root = (context-root-from-value-token $arg $context_names $bound_aliases)
                if $root == null {
                    continue
                }
                let raw_access = if $root == "" {
                    $access.raw_access
                } else {
                    $"($root).($access.raw_access)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def program-record-context-aliases [source: string context_names] {
    mut aliases = []
    let bound_aliases = (program-bound-context-root-aliases-base $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )

    mut changed = true
    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            let bindings = (
                (record-context-bindings $line $context_names $bound_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-wrapper-context-bindings $line $context_names $bound_aliases $identity_wrappers $wrapper_defs)
                | append (record-upsert-context-bindings $line $context_names $bound_aliases)
                | append (record-pipeline-flow-context-bindings $line $context_names $bound_aliases $identity_wrappers $root_wrapper_defs $aliases)
                | append (record-spread-context-bindings $line $aliases)
            )
            for binding in $bindings {
                let existing = (
                    $aliases
                    | where {|alias|
                        (
                            $alias.name == $binding.name
                            and $alias.field == $binding.field
                            and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                        )
                    }
                )
                if ($existing | is-empty) {
                    $aliases = ($aliases | append $binding)
                    $changed = true
                }
            }
        }
    }

    $aliases
}

def source-has-non-context-record-projection? [source: string context_names] {
    for line in ($source | lines) {
        for parsed in (
            $line
            | parse --regex '\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.[A-Za-z_][A-Za-z0-9_-]*\.'
        ) {
            if $parsed.name not-in $context_names {
                return true
            }
        }
    }

    false
}

def record-context-projection-kernel-features [source: string target context_names] {
    if (
        not ($source | str contains "let")
        and not ($source | str contains "mut")
        and not ($source | str contains "def ")
    ) {
        return []
    }
    if not (source-has-non-context-record-projection? $source $context_names) {
        return []
    }

    mut features = []
    let aliases = (program-record-context-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name).($alias.field)."
            let root = ($alias | get -o root | default "")
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $root == "" {
                    $raw_tail
                } else {
                    $"($root).($raw_tail)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def get-command-field-tail [segment: string] {
    let parsed = (
        $segment
        | str trim
        | parse --regex '^get\s+(?P<field>[A-Za-z_][A-Za-z0-9_-]*)(?P<tail>.*)$'
    )
    if ($parsed | is-empty) {
        return null
    }

    let row = ($parsed | first)
    {
        field: ($row.field | str trim)
        tail: ($row.tail | str trim)
    }
}

def context-root-from-get-input [input: string context_names bound_aliases] {
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let root = (context-root-from-value-token $normalized_input $context_names $bound_aliases)
    if $root != null {
        return $root
    }

    null
}

def get-segment-cell-path-tail [tail: string] {
    let parsed = (
        $tail
        | str trim
        | parse --regex '^[\)\s]*\.(?P<path>[A-Za-z_][A-Za-z0-9_.-]*)'
    )
    if ($parsed | is-empty) {
        return ""
    }

    normalize-context-path-token (($parsed | first).path)
}

def strip-leading-closure-header [line: string] {
    let trimmed = ($line | str trim)
    if not ($trimmed | str starts-with "{|") {
        return $trimmed
    }

    let parts = (($trimmed | str substring 2..) | split row "|")
    if ($parts | length) < 2 {
        return $trimmed
    }

    $parts | skip 1 | str join "|" | str trim
}

def context-get-projection-kernel-features [source: string target context_names] {
    if (not ($source | str contains "get")) or (not ($source | str contains "|")) {
        return []
    }
    let candidate_lines = (record-get-candidate-lines $source)
    if ($candidate_lines | is-empty) {
        return []
    }

    mut features = []
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)

    for line in $candidate_lines {
        let trimmed = ($line | str trim)
        let segments = (split-pipeline-segments $trimmed)

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        mut root = null

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                continue
            }

            if $root == null {
                $root = (context-root-from-get-input $input $context_names $bound_aliases)
                if $root == null {
                    continue
                }
            }

            let field_path = (normalize-context-path-token $parsed.field)
            if $field_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $field_path $target)
                )
                $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
            }

            let tail_path = (get-segment-cell-path-tail $parsed.tail)
            if $tail_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $tail_path $target)
                )
                $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
            }
        }
    }

    $features
}

def context-access-kernel-features-from-root-path [root path: string target] {
    let normalized_path = (normalize-context-path-token $path)
    let raw_access = if $normalized_path == "" {
        $root
    } else if $root == "" {
        $normalized_path
    } else {
        $"($root).($normalized_path)"
    }
    if $raw_access == "" {
        return []
    }

    context-access-kernel-features $raw_access $target
}

def record-get-candidate-lines [source: string] {
    mut candidates = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }
        let pipeline_line = (strip-leading-closure-header $trimmed)
        if (not ($pipeline_line | str contains "get")) or (not ($pipeline_line | str contains "|")) {
            continue
        }
        if not (line-invokes-command? $pipeline_line "get") {
            continue
        }

        let segments = (split-pipeline-segments $pipeline_line)
        if ($segments | length) < 2 {
            continue
        }

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        let normalized_input = (trim-simple-parentheses $input)
        if (
            ($normalized_input | str starts-with "$")
            or ($normalized_input | str starts-with "($")
            or ($normalized_input | str starts-with "{")
            or ($normalized_input | str starts-with "({")
            or not ((two-token-invocation $normalized_input) == null)
        ) {
            $candidates = ($candidates | append $pipeline_line)
        }
    }

    $candidates
}

def record-get-projection-kernel-features [source: string target context_names] {
    if (not ($source | str contains "get")) or (not ($source | str contains "|")) {
        return []
    }
    let candidate_lines = (record-get-candidate-lines $source)
    if ($candidate_lines | is-empty) {
        return []
    }

    mut features = []
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let record_aliases = (program-record-context-aliases $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let record_wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )

    for line in $candidate_lines {
        let trimmed = ($line | str trim)
        let segments = (split-pipeline-segments $trimmed)

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        mut root = null
        mut prefix_segments = []

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                if $root == null {
                    $prefix_segments = ($prefix_segments | append ($segment | str trim))
                }
                continue
            }

            if $root == null {
                $root = (
                    context-root-from-record-get
                        $input
                        $parsed.field
                        $record_aliases
                        $record_wrapper_defs
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
                if $root == null {
                    $root = (
                        context-root-from-record-pipeline-get
                            $input
                            $prefix_segments
                            $parsed.field
                            $record_aliases
                            $context_names
                            $bound_aliases
                            $identity_wrappers
                            $root_wrapper_defs
                    )
                }
                if $root == null {
                    continue
                }

                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root "" $target)
                )
            } else {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $parsed.field $target)
                )
                let field_path = (normalize-context-path-token $parsed.field)
                if $field_path != "" {
                    $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
                }
            }

            let tail_path = (get-segment-cell-path-tail $parsed.tail)
            if $tail_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $tail_path $target)
                )
                $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
            }
        }
    }

    $features
}

def source-has-context-root-projection? [source: string context_names] {
    for line in ($source | lines) {
        for context_name in $context_names {
            for raw_tail in (marker-tails-outside-simple-string $line $"$($context_name).") {
                let root = (normalize-context-field-token $raw_tail)
                if (context-projection-root? $root) {
                    return true
                }
            }
        }
    }

    if ($source | str contains "get") and ($source | str contains "|") {
        let aliases = (program-bound-context-root-aliases-base $source $context_names)
        if not ($aliases | is-empty) {
            return true
        }

        for line in (record-get-candidate-lines $source) {
            let segments = (split-pipeline-segments ($line | str trim))
            if ($segments | length) < 2 {
                continue
            }

            mut input = (($segments | first) | str trim)
            if ($input | str contains "=") {
                $input = (($input | split row "=" | last) | str trim)
            }
            if (context-root-from-get-input $input $context_names $aliases) != null {
                return true
            }
        }
    }

    if ($source | str contains "def ") {
        let root_wrappers = (context-root-wrapper-definitions $source)
        if not ($root_wrappers | is-empty) {
            return true
        }
    }

    false
}

def bound-context-projection-kernel-features [source: string target context_names] {
    if not ($source | str contains "let") and not ($source | str contains "mut") {
        return []
    }
    if not (source-has-context-root-projection? $source $context_names) {
        return []
    }

    mut features = []
    let aliases = (program-bound-context-root-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name)."
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $alias.root == "" {
                    $raw_tail
                } else {
                    $"($alias.root).($raw_tail)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def program-kfunc-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        for raw_call in (command-invocation-tails $line "kfunc-call") {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let kfunc_name = (normalize-kfunc-name-token $raw_name)
            if $kfunc_name not-in $names {
                $names = ($names | append $kfunc_name)
            }
        }
    }

    $names
}

def program-helper-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        for raw_call in (command-invocation-tails $line "helper-call") {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let helper_name = (normalize-helper-name-token $raw_name)
            if $helper_name not-in $names {
                $names = ($names | append $helper_name)
            }
        }
    }

    $names
}

def program-map-kernel-features [source: string] {
    mut features = []
    mut map_kind_bindings = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }

        if (line-invokes-command? $trimmed "helper-call") {
            let feature = (helper-call-map-kind-kernel-feature $trimmed $map_kind_bindings)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
            $map_kind_bindings = (update-helper-call-map-kind-bindings-for-line $map_kind_bindings $trimmed)
            continue
        }

        if not (line-invokes-map-kind-surface? $trimmed) {
            continue
        }

        let kind = (source-line-effective-map-kind $trimmed $map_kind_bindings)
        if $kind != null and $kind != "" {
            let feature = (map-kind-kernel-feature $kind)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
        $map_kind_bindings = (update-map-kind-bindings-for-line $map_kind_bindings $trimmed)
    }

    if (source-invokes-command? $source "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PROG_ARRAY])
    }

    $features
}

def program-reserved-map-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }

        if (
            (line-invokes-command? $trimmed "emit")
            or (line-contains-code-marker? $trimmed " events")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_RINGBUF])
        }
        if (
            (line-invokes-command? $trimmed "count")
            or (line-invokes-command? $trimmed "histogram")
            or (line-invokes-command? $trimmed "start-timer")
            or (line-invokes-command? $trimmed "stop-timer")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_HASH])
        }
        if (line-contains-code-marker? $trimmed " user_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_USER_RINGBUF])
        }
        if (line-contains-code-marker? $trimmed " perf_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY])
        }
        if (
            (line-contains-code-marker? $trimmed " kstacks")
            or (line-contains-code-marker? $trimmed " ustacks")
            or (line-contains-code-marker? $trimmed ".kstack")
            or (line-contains-code-marker? $trimmed ".ustack")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_STACK_TRACE])
        }
    }

    $features
}

def program-map-value-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if not ((line-invokes-command? $trimmed "map-define") and (line-contains-code-marker? $trimmed "--value-type")) {
            continue
        }

        for entry in $MAP_VALUE_KERNEL_FEATURES {
            if ($trimmed | str contains $entry.token) {
                $features = (append-missing-kernel-features $features [$entry.feature])
            }
        }
        if ($trimmed | str contains "bpf_list_head:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE])
        }
        if ($trimmed | str contains "bpf_rb_root:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE])
        }
    }

    $features
}

def variable-token-used-outside-simple-string? [text: string name: string] {
    for tail in (marker-tails-outside-simple-string $text $"$($name)") {
        if $tail == "" {
            return true
        }
        let first = ($tail | str substring 0..0)
        if $first in [" " "\t" "." "," ":" ")" "}" "]" "|" ";"] {
            return true
        }
    }

    false
}

def aggregate-rhs-contains-context-token? [rhs: string context_names context_root_aliases] {
    for context_name in $context_names {
        if (variable-token-used-outside-simple-string? $rhs $context_name) {
            return true
        }
    }

    for alias in $context_root_aliases {
        let name = ($alias | get -o name)
        if $name != null and (variable-token-used-outside-simple-string? $rhs $name) {
            return true
        }
    }

    false
}

def line-declares-readonly-aggregate-constant? [line: string context_names context_root_aliases] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let rhs = (declaration-rhs-token $assignment)
        let aggregate_rhs = (trim-simple-parentheses $rhs)
        if (aggregate-rhs-contains-context-token? $aggregate_rhs $context_names $context_root_aliases) {
            continue
        }
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (($compact | str starts-with "{") and $compact != "{}") {
            return true
        }
        if (($compact | str starts-with "[") and $compact != "[]") {
            return true
        }
        if (($compact | str starts-with "0x[") and $compact != "0x[]") {
            return true
        }
    }

    false
}

def line-declares-aggregate-literal? [line: string] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let aggregate_rhs = (trim-simple-parentheses (declaration-rhs-token $assignment))
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (($compact | str starts-with "{") and $compact != "{}") {
            return true
        }
        if (($compact | str starts-with "[") and $compact != "[]") {
            return true
        }
        if (($compact | str starts-with "0x[") and $compact != "0x[]") {
            return true
        }
    }

    false
}

def line-declares-aggregate-literal-with-variable? [line: string] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let aggregate_rhs = (trim-simple-parentheses (declaration-rhs-token $assignment))
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (
            (($compact | str starts-with "{") and $compact != "{}")
            or (($compact | str starts-with "[") and $compact != "[]")
            or (($compact | str starts-with "0x[") and $compact != "0x[]")
        ) and (line-contains-code-marker? $aggregate_rhs "$") {
            return true
        }
    }

    false
}

def line-invokes-global-command? [line: string] {
    for command in ["global-define" "global-get" "global-set"] {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def line-declares-annotated-mut-global? [line: string] {
    for tail in (command-invocation-tails $line "mut") {
        let lhs = ($tail | split row "=" | first | str trim)
        if ($lhs | str contains ":") {
            return true
        }
    }

    false
}

def program-global-kernel-features [source: string] {
    mut variable_aggregate_lines = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if ($trimmed | str starts-with "#") {
            continue
        }

        if (line-invokes-global-command? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if (line-declares-annotated-mut-global? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if not (line-declares-aggregate-literal? $trimmed) {
            continue
        }

        if not (line-declares-aggregate-literal-with-variable? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        $variable_aggregate_lines = ($variable_aggregate_lines | append $trimmed)
    }

    if ($variable_aggregate_lines | is-empty) {
        return []
    }

    let context_names = (program-context-variable-names $source)
    let context_root_aliases = (program-bound-context-root-aliases $source $context_names)
    mut context_aliases = $context_root_aliases
    mut record_context_aliases_loaded = false

    for trimmed in $variable_aggregate_lines {
        if not (line-declares-readonly-aggregate-constant? $trimmed $context_names $context_aliases) {
            continue
        }

        if not $record_context_aliases_loaded {
            $context_aliases = (
                $context_aliases
                | append (program-record-context-aliases $source $context_names)
            )
            $record_context_aliases_loaded = true
        }
        if not (line-declares-readonly-aggregate-constant? $trimmed $context_names $context_aliases) {
            continue
        }

        return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
    }

    []
}

def program-helper-kernel-features [source: string] {
    mut features = []

    for helper_name in (program-helper-names $source) {
        let feature = (helper-kernel-feature $helper_name)
        if $feature != null {
            $features = (append-missing-kernel-features $features [$feature])
        }
    }

    $features
}

def program-kfunc-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let cgroup_sock_addr_hook = if ($target_text | str starts-with "cgroup_sock_addr:") {
        $target_text | split row ":" | last
    } else {
        ""
    }
    let has_kfunc_call = ($source | str contains "kfunc-call")
    let may_assign_unix_sun_path = (
        ($target_text | str starts-with "cgroup_sock_addr:")
        and ($cgroup_sock_addr_hook | str ends-with "_unix")
        and ($source | str contains "sun_path")
    )

    if not $has_kfunc_call and not $may_assign_unix_sun_path {
        return []
    }

    if $has_kfunc_call {
        for kfunc_name in (program-kfunc-names $source) {
            let feature = (program-kfunc-kernel-feature $kfunc_name $target_text)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
    }

    if not $may_assign_unix_sun_path {
        return $features
    }

    let context_names = (program-context-variable-names $source)
    let record_context_aliases = (program-record-context-aliases $source $context_names)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if (
            (line-assigns-context-field? $trimmed $context_names ["sun_path"])
            or (line-assigns-record-context-field? $trimmed $record_context_aliases ["sun_path"] [""])
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH])
        }
    }

    $features
}

def callback-trusted-btf-param-indexes [helper_name: string] {
    if $helper_name in ["bpf_timer_set_callback" "bpf_for_each_map_elem"] {
        return [0]
    }
    if $helper_name == "bpf_find_vma" {
        return [0 1]
    }

    []
}

def helper-call-name-from-line [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    normalize-helper-name-token (($tails | first | str trim | split row " " | first))
}

def closure-param-names-from-line [line: string] {
    let closure_parts = ($line | split row "{|")
    if ($closure_parts | length) <= 1 {
        return []
    }

    let raw_closure = ($closure_parts | skip 1 | first)
    let param_parts = ($raw_closure | split row "|")
    if ($param_parts | length) == 0 {
        return []
    }

    $param_parts
    | first
    | str replace --all "," " "
    | split row " "
    | each {|param| $param | str trim }
    | where {|param| $param != "" }
}

def helper-call-trusted-btf-callback-roots [line: string] {
    let helper_name = (helper-call-name-from-line $line)
    if $helper_name == null {
        return []
    }

    let trusted_indexes = (callback-trusted-btf-param-indexes $helper_name)
    if ($trusted_indexes | is-empty) {
        return []
    }

    let params = (closure-param-names-from-line $line)
    if ($params | is-empty) {
        return []
    }

    mut roots = []
    for idx in $trusted_indexes {
        if $idx < ($params | length) {
            let param = ($params | get $idx)
            if $param not-in $roots {
                $roots = ($roots | append $param)
            }
        }
    }

    $roots
}

def program-callback-btf-kernel-features [source: string] {
    mut features = []
    mut trusted_roots = []

    for line in ($source | lines) {
        let callback_roots = (helper-call-trusted-btf-callback-roots $line)
        if not ($callback_roots | is-empty) {
            $trusted_roots = $callback_roots
        }

        for root in $trusted_roots {
            let prefix = $"$($root)."
            let parts = ($line | split row $prefix)
            if ($parts | length) <= 1 {
                continue
            }

            for raw_tail in ($parts | skip 1) {
                let field = (normalize-context-field-token $raw_tail)
                if $field != "" {
                    # Trusted-BTF callback scalar projections lower as direct
                    # loads, not probe_read_kernel helper calls.
                    continue
                }
            }
        }

        let trimmed = ($line | str trim)
        if not ($trusted_roots | is-empty) and ($trimmed | str starts-with "}") {
            $trusted_roots = []
        }
    }

    $features
}

def program-context-field-kernel-features [source: string target] {
    mut features = []
    let context_names = (program-context-variable-names $source)

    for line in ($source | lines) {
        for context_name in $context_names {
            for raw_access in (marker-tails-outside-simple-string $line $"$($context_name).") {
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }

                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features = (append-missing-kernel-features $features (user-function-context-field-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (multi-param-user-function-context-field-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (bound-context-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (record-context-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (context-get-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (record-get-projection-kernel-features $source $target $context_names))

    $features
}

def program-surface-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let context_names = (program-context-variable-names $source)
    mut record_context_aliases = []
    mut record_context_aliases_loaded = false
    mut map_kind_bindings = []
    let target_uses_skb_cgroup_helper = (
        ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "lwt_in:")
        or ($target_text | str starts-with "lwt_out:")
        or ($target_text | str starts-with "lwt_xmit:")
        or ($target_text | str starts-with "lwt_seg6local:")
    )

    if (source-invokes-command? $source "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_TAIL_CALL])
    }
    if (source-invokes-command-with-tail-prefix? $source "random" "int") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_GET_PRANDOM_U32])
    }
    if (source-invokes-command? $source "read-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_USER_STR])
    }
    if (source-invokes-command? $source "read-kernel-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR])
    }
    if (source-invokes-command? $source "emit") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_RINGBUF_OUTPUT])
    }
    if ((source-invokes-command? $source "count") or (source-invokes-command? $source "histogram")) {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if (source-invokes-command? $source "start-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if (source-invokes-command? $source "stop-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_DELETE_ELEM
        ])
    }
    for line in ($source | lines) {
        if (line-invokes-command? $line "helper-call") {
            $map_kind_bindings = (
                update-helper-call-map-kind-bindings-for-line
                    $map_kind_bindings
                    ($line | str trim)
            )
            continue
        }

        let trimmed = ($line | str trim)
        let assigns_sysctl_new_value = (
            line-assigns-context-field? $trimmed $context_names ["new_value" "sysctl_new_value"]
        )
        let target_supports_ctx_sk_assign = (
            ($target_text | str starts-with "sk_lookup:")
            or ($target_text | str starts-with "tc_action:")
            or (($target_text | str starts-with "tc:") and ($target_text | str contains ":ingress"))
            or (($target_text | str starts-with "tcx:") and ($target_text | str contains ":ingress"))
        )
        let may_have_record_context_helper_write = (
            (($target_text | str starts-with "cgroup_sysctl:") and (
                ($trimmed | str contains ".new_value")
                or ($trimmed | str contains ".sysctl_new_value")
            ))
            or ($target_supports_ctx_sk_assign and (
                ($trimmed | str contains ".sk")
                or ($trimmed | str contains ".sock")
                or ($trimmed | str contains ".socket")
            ))
            or (($target_text | str starts-with "sock_ops:") and ($trimmed | str contains ".cb_flags"))
        )
        if $may_have_record_context_helper_write and not $record_context_aliases_loaded {
            $record_context_aliases = (program-record-context-aliases $source $context_names)
            $record_context_aliases_loaded = true
        }
        let assigns_ctx_sk = (
            line-assigns-context-field? $trimmed $context_names ["sk" "sock" "socket"]
        )
        let assigns_record_ctx_sk = (
            $target_supports_ctx_sk_assign
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["sk" "sock" "socket"] [""])
        )
        let assigns_record_sysctl_new_value = (
            ($target_text | str starts-with "cgroup_sysctl:")
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["new_value" "sysctl_new_value"] [""])
        )
        let assigns_record_sock_ops_cb_flags = (
            ($target_text | str starts-with "sock_ops:")
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["cb_flags"] [""])
        )
        let inferred_map_kind = (source-line-effective-map-kind $trimmed $map_kind_bindings)
        let map_kind = if $inferred_map_kind == null { "hash" } else { $inferred_map_kind }
        if (line-invokes-command? $trimmed "map-get") and (generic-map-lookup-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
        }
        if (line-invokes-command? $trimmed "map-put") and (generic-map-update-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM])
        }
        if ($target_text | str starts-with "sock_ops:") and (line-invokes-command? $trimmed "map-put") {
            if $map_kind == "sockmap" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE])
            } else if $map_kind == "sockhash" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE])
            }
        }
        if (line-invokes-command? $trimmed "map-delete") and (generic-map-delete-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_DELETE_ELEM])
        }
        if ((line-invokes-command? $trimmed "map-get") or (line-invokes-command? $trimmed "map-contains")) {
            let local_storage_feature = (local-storage-get-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if (line-invokes-command? $trimmed "map-delete") {
            let local_storage_feature = (local-storage-delete-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if (line-invokes-command? $trimmed "map-push") and ($map_kind in ["queue" "stack" "bloom-filter"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PUSH_ELEM])
        }
        if (line-invokes-command? $trimmed "map-peek") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
        }
        if (line-invokes-command? $trimmed "map-pop") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_POP_ELEM])
        }
        if (line-invokes-command? $trimmed "map-contains") {
            if $map_kind == "bloom-filter" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
            } else if (generic-map-lookup-kind? $map_kind) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
            }
        }
        if (line-invokes-command? $trimmed "redirect-map") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_MAP])
        }
        if (line-invokes-command? $trimmed "map-contains") and ($map_kind == "cgroup-array") {
            if $target_uses_skb_cgroup_helper {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP])
            } else {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP])
            }
        }
        if (line-invokes-command? $trimmed "assign-socket") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
            let socket_context_feature = (context-field-kernel-feature "sk" $target)
            if $socket_context_feature != null {
                $features = (append-missing-kernel-features $features [$socket_context_feature])
            }
        }
        if ($target_text | str starts-with "cgroup_sysctl:") and ($assigns_sysctl_new_value or $assigns_record_sysctl_new_value) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE])
        }
        if $target_supports_ctx_sk_assign and ($assigns_ctx_sk or $assigns_record_ctx_sk) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--apply") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_APPLY_BYTES])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--cork") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_CORK_BYTES])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PULL_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--push") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PUSH_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--pop") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_POP_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_PULL_DATA])
        }
        if (line-invokes-command? $trimmed "redirect-socket") {
            if ($target_text | str starts-with "sk_msg:") {
                if $map_kind == "sockhash" {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_skb:") or ($target_text | str starts-with "sk_skb_parser:") {
                if $map_kind == "sockhash" {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_reuseport:") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT])
            }
        }
        if ($target_text | str starts-with "sock_ops:") and ((line-assigns-context-field? $trimmed $context_names ["cb_flags"]) or $assigns_record_sock_ops_cb_flags) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET])
        }
        if ($target_text | str starts-with "xdp:") {
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--meta") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_META])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL])
            }
        } else {
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--room") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM])
            }
        }
        if (line-invokes-command? $trimmed "redirect") {
            if ($trimmed | str contains "--peer") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_PEER])
            } else if ($trimmed | str contains "--neigh") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_NEIGH])
            } else if (
                ($target_text | str starts-with "xdp:")
                or ($target_text | str starts-with "tc_action:")
                or ($target_text | str starts-with "tc:")
                or ($target_text | str starts-with "tcx:")
                or ($target_text | str starts-with "netkit:")
                or ($target_text | str starts-with "lwt_xmit:")
            ) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT])
            }
        }
        $map_kind_bindings = (update-map-kind-bindings-for-line $map_kind_bindings $trimmed)
    }

    $features
}

def struct-ops-target-sleepable? [target: string] {
    if not ($target | str starts-with "struct_ops:sched_ext_ops.") {
        return false
    }

    let callback = (
        $target
        | split row "struct_ops:sched_ext_ops."
        | get 1
        | split row ":"
        | first
    )

    $callback in $SCHED_EXT_SLEEPABLE_CALLBACKS
}

def program-struct-ops-kernel-features [source: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "struct_ops:sched_ext_ops") {
        return []
    }

    mut features = []
    if (struct-ops-target-sleepable? $target_text) {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
    }

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        for callback in $SCHED_EXT_SLEEPABLE_CALLBACKS {
            if ($trimmed | str starts-with $"($callback):") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
            }
        }
    }

    $features
}

def target-kernel-features [target] {
    if $target == null {
        return []
    }

    mut features = []

    if ($target | str starts-with "fentry.s:") or ($target | str starts-with "fexit.s:") or ($target | str starts-with "fmod_ret.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "fentry:") or ($target | str starts-with "fexit:") or ($target | str starts-with "fmod_ret:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
    } else if ($target | str starts-with "tp_btf:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
    } else if ($target | str starts-with "lsm_cgroup:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM_CGROUP)
    } else if ($target | str starts-with "lsm.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "lsm:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
    } else if ($target | str starts-with "struct_ops:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_STRUCT_OPS)
        if ($target | str contains "tcp_congestion_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_TCP_CONGESTION)
        }
        if ($target | str contains "hid_bpf_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_HID_BPF)
        }
        if ($target | str contains "sched_ext_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT)
        }
        if ($target | str contains "Qdisc_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_QDISC)
        }
        if (struct-ops-target-sleepable? $target) {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "kprobe.multi:") or ($target | str starts-with "kretprobe.multi:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_KPROBE_MULTI)
    } else if ($target | str starts-with "kprobe:") or ($target | str starts-with "kretprobe:") or ($target | str starts-with "ksyscall:") or ($target | str starts-with "kretsyscall:") or ($target | str starts-with "uprobe:") or ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe:") or ($target | str starts-with "uretprobe.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        if ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "uprobe.multi:") or ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi:") or ($target | str starts-with "uretprobe.multi.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_UPROBE_MULTI)
        if ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "raw_tracepoint.w:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT_WRITABLE)
    } else if ($target | str starts-with "raw_tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
    } else if ($target | str starts-with "tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACEPOINT)
    } else if ($target | str starts-with "perf_event:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_PERF_EVENT)
    } else if ($target | str starts-with "xdp:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_XDP)
        let xdp_parts = ($target | split row ":")
        if ("devmap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DEVMAP)
        } else if ("cpumap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_CPUMAP)
        } else if ("hw" in $xdp_parts) or ("hardware" in $xdp_parts) or ("offload" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_HW)
        } else if ("drv" in $xdp_parts) or ("driver" in $xdp_parts) or ("native" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DRV)
        } else {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_SKB)
        }
        if ("frags" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_MULTI_BUFFER)
        }
    } else if ($target | str starts-with "socket_filter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCKET_FILTER)
    } else if ($target | str starts-with "tc:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_CLS)
    } else if ($target | str starts-with "tc_action:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_ACT)
    } else if ($target | str starts-with "tcx:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_TCX)
    } else if ($target | str starts-with "netkit:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_NETKIT)
    } else if ($target | str starts-with "flow_dissector:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_FLOW_DISSECTOR)
    } else if ($target | str starts-with "netfilter:") {
        $features = ($features | append $KERNEL_FEATURE_NETFILTER_LINK)
        let netfilter_parts = ($target | split row ":")
        if ("defrag" in $netfilter_parts) {
            $features = ($features | append $KERNEL_FEATURE_NETFILTER_DEFRAG)
        }
    } else if ($target | str starts-with "lwt_seg6local:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT_SEG6LOCAL)
    } else if ($target | str starts-with "lwt_in:") or ($target | str starts-with "lwt_out:") or ($target | str starts-with "lwt_xmit:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
    } else if ($target | str starts-with "sk_lookup:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_LOOKUP)
    } else if ($target | str starts-with "sk_msg:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_MSG)
    } else if ($target | str starts-with "sk_skb:") or ($target | str starts-with "sk_skb_parser:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_SKB)
    } else if ($target | str starts-with "sk_reuseport:") {
        $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_ATTACH)
        let sk_reuseport_parts = ($target | split row ":")
        if ("migrate" in $sk_reuseport_parts) {
            $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_MIGRATION)
        }
    } else if ($target | str starts-with "cgroup_skb:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SKB)
    } else if ($target | str starts-with "cgroup_sock_addr:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK_ADDR)
        let cgroup_sock_addr_hook = ($target | split row ":" | last)
        if ($cgroup_sock_addr_hook | str ends-with "_unix") {
            $features = ($features | append $KERNEL_FEATURE_ATTACH_CGROUP_UNIX_SOCK_ADDR)
        }
    } else if ($target | str starts-with "cgroup_sockopt:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCKOPT)
    } else if ($target | str starts-with "cgroup_sock:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK)
    } else if ($target | str starts-with "cgroup_device:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_DEVICE)
    } else if ($target | str starts-with "cgroup_sysctl:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SYSCTL)
    } else if ($target | str starts-with "sock_ops:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCK_OPS)
    } else if ($target | str starts-with "lirc_mode2:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LIRC_MODE2)
    } else if ($target | str starts-with "iter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_ITER)
        let iter_target = ($target | split row ":" | get 1)
        let iter_feature = (iter-target-kernel-feature $iter_target)
        if $iter_feature != null {
            $features = ($features | append $iter_feature)
        }
    } else if ($target | str starts-with "syscall:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SYSCALL)
    } else if ($target | str starts-with "freplace:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_EXTENSION)
    }

    $features
}

def source-statement-lines [source: string] {
    $source
    | lines
    | each {|line| $line | str trim }
    | where {|line| $line != "" and not ($line | str starts-with "#") }
}

def line-has-statement-keyword? [line: string keyword: string] {
    not ((command-invocation-tails $line $keyword) | is-empty)
}

def line-has-callback-subprogram-literal? [line: string] {
    for command in ["helper-call" "kfunc-call"] {
        for raw_call in (command-invocation-tails $line $command) {
            if (line-contains-code-marker? $raw_call "{|") {
                return true
            }
        }
    }

    false
}

def program-language-kernel-features [source: string] {
    mut features = []

    for line in (source-statement-lines $source) {
        if (line-has-statement-keyword? $line "def") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS])
        }

        if (line-has-callback-subprogram-literal? $line) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS])
        }

        if (line-has-statement-keyword? $line "for") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BOUNDED_LOOPS])
        }
    }

    $features
}

def fixture-kernel-features [fixture] {
    mut features = (optional $fixture kernel_features [])
    $features = (append-missing-kernel-features $features (target-kernel-features ($fixture | get -o target)))
    let program = (fixture-program $fixture)
    $features = (append-missing-kernel-features $features (program-language-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-reserved-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-value-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-global-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-helper-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-kfunc-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-callback-btf-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-context-field-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-surface-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-struct-ops-kernel-features $program ($fixture | get -o target)))

    let legacy_min_kernel = ($fixture | get -o min_kernel)
    let legacy_min_kernel_source = ($fixture | get -o min_kernel_source)
    if $legacy_min_kernel != null {
        $features = (
            $features
            | append {
                key: "fixture"
                min_kernel: $legacy_min_kernel
                source: $legacy_min_kernel_source
            }
        )
    }

    $features
}

def effective-min-kernel-from-features [features] {
    let versions = (
        $features
        | each {|feature| $feature.min_kernel }
    )

    kernel-version-max $versions
}

def effective-max-kernel-exclusive-from-features [features] {
    let versions = (
        $features
        | each {|feature| $feature | get -o max_kernel_exclusive }
        | where {|version| $version != null and $version != "" }
    )

    kernel-version-min $versions
}

def effective-max-kernel-exclusive-sources-from-features [features] {
    let max_kernel = (effective-max-kernel-exclusive-from-features $features)
    if $max_kernel == null {
        return []
    }

    $features
    | where {|feature| ($feature | get -o max_kernel_exclusive) == $max_kernel }
    | each {|feature| $feature | get -o max_kernel_exclusive_source }
    | where {|source| $source != null and $source != "" }
    | uniq
}

def effective-min-kernel-sources-from-features [features] {
    let min_kernel = (effective-min-kernel-from-features $features)
    if $min_kernel == null {
        return []
    }

    $features
    | where {|feature| $feature.min_kernel == $min_kernel }
    | each {|feature| $feature.source }
    | uniq
}

def kernel-feature-compatibility [min_kernel max_kernel kernel_release] {
    if $kernel_release == null or ($min_kernel == null and $max_kernel == null) {
        return {
            compatible: true
            required: ""
            reason: ""
        }
    }

    let too_old = ($min_kernel != null and not (kernel-version-at-least $kernel_release $min_kernel))
    let too_new = ($max_kernel != null and not (kernel-version-before $kernel_release $max_kernel))
    let compatible = (not $too_old and not $too_new)
    let reason = if $too_old {
        $"kernel>=($min_kernel)"
    } else if $too_new {
        $"kernel<($max_kernel)"
    } else {
        ""
    }
    {
        compatible: $compatible
        required: ($min_kernel | default "")
        maximum_exclusive: ($max_kernel | default "")
        reason: $reason
    }
}

def fixture-effective-min-kernel [fixture] {
    effective-min-kernel-from-features (fixture-kernel-features $fixture)
}

def fixture-effective-max-kernel-exclusive [fixture] {
    effective-max-kernel-exclusive-from-features (fixture-kernel-features $fixture)
}

def fixture-effective-min-kernel-sources [fixture] {
    effective-min-kernel-sources-from-features (fixture-kernel-features $fixture)
}

def fixture-kernel-compatibility [fixture kernel_release] {
    let features = (fixture-kernel-features $fixture)
    kernel-feature-compatibility (effective-min-kernel-from-features $features) (effective-max-kernel-exclusive-from-features $features) $kernel_release
}

def test-lane-rank [lane: string] {
    if $lane == "host-safe" {
        0
    } else if $lane == "host-gated" {
        1
    } else if $lane == "dry-run" {
        2
    } else if $lane == "vm-only" {
        3
    } else {
        0
    }
}

def stricter-test-lane [left: string right: string] {
    if (test-lane-rank $right) > (test-lane-rank $left) {
        $right
    } else {
        $left
    }
}

def aggregate-test-lanes [lanes] {
    mut lane = "host-safe"

    for candidate in $lanes {
        if $candidate != null and $candidate != "" {
            $lane = (stricter-test-lane $lane $candidate)
        }
    }

    $lane
}

def kernel-feature-default-test-lane [feature] {
    let key = ($feature | get -o key | default "")

    if ($key | str starts-with "struct_ops:") {
        return "vm-only"
    }

    if $key in [
        "program:BPF_PROG_TYPE_STRUCT_OPS"
        "program:BPF_PROG_TYPE_LWT"
        "attach:netfilter-link"
    ] {
        return "vm-only"
    }

    if $key in [
        "program:BPF_PROG_TYPE_EXT"
        "program:BPF_PROG_TYPE_SYSCALL"
    ] {
        return "dry-run"
    }

    if $key in [
        "section:raw_tracepoint.w"
        "program:BPF_PROG_TYPE_SOCKET_FILTER"
        "program:BPF_PROG_TYPE_XDP"
        "attach:xdp-skb"
        "attach:xdp-drv"
        "attach:xdp-hw"
        "attach:BPF_XDP_DEVMAP"
        "attach:BPF_XDP_CPUMAP"
        "section:xdp.frags"
        "program:BPF_PROG_TYPE_SCHED_CLS"
        "program:BPF_PROG_TYPE_SCHED_ACT"
        "program:BPF_PROG_TYPE_SK_LOOKUP"
        "attach:BPF_LSM_CGROUP"
        "program:BPF_PROG_TYPE_FLOW_DISSECTOR"
        "attach:tcx"
        "attach:netkit"
        "attach:netfilter-defrag"
        "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"
        "program:BPF_PROG_TYPE_SK_MSG"
        "program:BPF_PROG_TYPE_SK_SKB"
        "attach:BPF_SK_REUSEPORT_SELECT"
        "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
        "program:BPF_PROG_TYPE_CGROUP_SKB"
        "program:BPF_PROG_TYPE_CGROUP_SOCK"
        "program:BPF_PROG_TYPE_CGROUP_DEVICE"
        "program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
        "program:BPF_PROG_TYPE_CGROUP_SYSCTL"
        "program:BPF_PROG_TYPE_CGROUP_SOCKOPT"
        "program:BPF_PROG_TYPE_SOCK_OPS"
        "attach:BPF_CGROUP_UNIX_SOCK_ADDR"
        "program:BPF_PROG_TYPE_LIRC_MODE2"
    ] {
        return "host-gated"
    }

    "host-safe"
}

def fixture-default-test-lane-from-features [fixture features] {
    let explicit = ($fixture | get -o default_test_lane)
    if $explicit != null {
        return $explicit
    }

    let lanes = (
        $features
        | each {|feature| kernel-feature-default-test-lane $feature }
    )
    aggregate-test-lanes $lanes
}

def fixture-default-test-lane [fixture] {
    fixture-default-test-lane-from-features $fixture (fixture-kernel-features $fixture)
}

def kernel-feature-labels [features] {
    $features
    | each {|feature|
        let max_kernel = ($feature | get -o max_kernel_exclusive)
        if $max_kernel == null or $max_kernel == "" {
            $"($feature.key)>=($feature.min_kernel)"
        } else {
            $"($feature.key)>=($feature.min_kernel),<($max_kernel)"
        }
    }
}

def fixture-tier [fixture] {
    let explicit = ($fixture | get -o tier)
    if $explicit != null {
        return $explicit
    }

    let requirements = (
        optional $fixture requires []
        | append (optional $fixture kernel_requires [])
    )

    if ($requirements | any {|feature| ($feature in ["kernel-btf" "tracefs"]) or ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) }) {
        "btf"
    } else {
        "fast"
    }
}

def fixture-summary [fixture compat_kernel] {
    let kernel_features = (fixture-kernel-features $fixture)
    fixture-summary-from-derived (fixture-derived-metadata $fixture $kernel_features) $compat_kernel
}

def fixture-derived-metadata [fixture kernel_features] {
    let effective_min_kernel = (effective-min-kernel-from-features $kernel_features)
    let effective_max_kernel_exclusive = (effective-max-kernel-exclusive-from-features $kernel_features)
    let default_test_lane = (fixture-default-test-lane-from-features $fixture $kernel_features)

    {
        fixture: $fixture
        name: $fixture.name
        target: (optional $fixture target "")
        category: (optional $fixture category "")
        tier: (fixture-tier $fixture)
        local: $fixture.local
        kernel: $fixture.kernel
        requires: (optional $fixture requires [])
        kernel_requires: (optional $fixture kernel_requires [])
        kernel_features: $kernel_features
        default_test_lane: $default_test_lane
        default_test_lane_description: (test-lane-description $default_test_lane)
        effective_min_kernel_raw: $effective_min_kernel
        effective_max_kernel_exclusive_raw: $effective_max_kernel_exclusive
        effective_min_kernel_sources: (effective-min-kernel-sources-from-features $kernel_features)
        effective_max_kernel_exclusive_sources: (effective-max-kernel-exclusive-sources-from-features $kernel_features)
        min_kernel: (optional $fixture min_kernel "")
        min_kernel_source: (optional $fixture min_kernel_source "")
        tags: (optional $fixture tags [])
    }
}

def fixture-summary-from-derived [derived compat_kernel] {
    let compatibility = (
        kernel-feature-compatibility
            $derived.effective_min_kernel_raw
            $derived.effective_max_kernel_exclusive_raw
            $compat_kernel
    )

    {
        name: $derived.name
        target: $derived.target
        category: $derived.category
        tier: $derived.tier
        local: $derived.local
        kernel: $derived.kernel
        requires: $derived.requires
        kernel_requires: $derived.kernel_requires
        kernel_features: $derived.kernel_features
        default_test_lane: $derived.default_test_lane
        default_test_lane_description: $derived.default_test_lane_description
        effective_min_kernel: ($derived.effective_min_kernel_raw | default "")
        effective_max_kernel_exclusive: ($derived.effective_max_kernel_exclusive_raw | default "")
        effective_min_kernel_sources: $derived.effective_min_kernel_sources
        effective_max_kernel_exclusive_sources: $derived.effective_max_kernel_exclusive_sources
        compat_kernel: ($compat_kernel | default "")
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
        min_kernel: $derived.min_kernel
        min_kernel_source: $derived.min_kernel_source
        tags: $derived.tags
    }
}

def fixture-status-count [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def fixture-has-effective-min-kernel [fixture] {
    (fixture-effective-min-kernel $fixture) != null
}

def kernel-accept-versioned-count [fixtures versioned: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| (fixture-has-effective-min-kernel $fixture) == $versioned }
    | length
}

def kernel-accept-compatible-count [fixtures kernel_release compatible: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| fixture-has-effective-min-kernel $fixture }
    | where {|fixture| (fixture-kernel-compatibility $fixture $kernel_release).compatible == $compatible }
    | length
}

def kernel-accept-compat-reason-count [fixtures kernel_release reason_prefix: string] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| ((fixture-kernel-compatibility $fixture $kernel_release).reason | str starts-with $reason_prefix) }
    | length
}

def fixture-test-lane-count [fixtures lane: string] {
    $fixtures
    | where {|fixture| (fixture-default-test-lane $fixture) == $lane }
    | length
}

def fixture-matrix-summary [fixture compat_kernel] {
    let kernel_features = (fixture-kernel-features $fixture)
    fixture-matrix-summary-from-derived (fixture-derived-metadata $fixture $kernel_features) $compat_kernel
}

def fixture-matrix-summary-from-derived [derived compat_kernel] {
    let compatibility = (
        kernel-feature-compatibility
            $derived.effective_min_kernel_raw
            $derived.effective_max_kernel_exclusive_raw
            $compat_kernel
    )

    {
        tier: $derived.tier
        category: $derived.category
        local: $derived.local
        kernel: $derived.kernel
        default_test_lane: $derived.default_test_lane
        has_effective_min_kernel: ($derived.effective_min_kernel_raw != null)
        has_effective_max_kernel_exclusive: ($derived.effective_max_kernel_exclusive_raw != null)
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
    }
}

def matrix-status-count [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def matrix-kernel-accept-versioned-count [fixtures versioned: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_min_kernel == $versioned }
    | length
}

def matrix-kernel-accept-bounded-count [fixtures bounded: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_max_kernel_exclusive == $bounded }
    | length
}

def matrix-kernel-accept-compatible-count [fixtures compatible: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_min_kernel }
    | where {|fixture| $fixture.compatible_with_compat_kernel == $compatible }
    | length
}

def matrix-kernel-accept-compat-reason-count [fixtures reason_prefix: string] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| ($fixture.compat_kernel_reason | str starts-with $reason_prefix) }
    | length
}

def matrix-test-lane-count [fixtures lane: string] {
    $fixtures
    | where {|fixture| $fixture.default_test_lane == $lane }
    | length
}

def fixture-matrix-rows [fixtures compat_kernel] {
    let matrix_fixtures = (
        $fixtures
        | each {|fixture| fixture-matrix-summary $fixture $compat_kernel }
    )

    fixture-matrix-rows-from-matrix-summaries $matrix_fixtures $compat_kernel
}

def fixture-matrix-rows-from-derived [derived_fixtures compat_kernel] {
    let matrix_fixtures = (
        $derived_fixtures
        | each {|fixture| fixture-matrix-summary-from-derived $fixture $compat_kernel }
    )

    fixture-matrix-rows-from-matrix-summaries $matrix_fixtures $compat_kernel
}

def fixture-matrix-rows-from-matrix-summaries [matrix_fixtures compat_kernel] {
    mut rows = []

    for tier in $VALID_TIERS {
        let tier_fixtures = (
            $matrix_fixtures
            | where {|fixture| $fixture.tier == $tier }
        )

        if (($tier_fixtures | length) == 0) {
            continue
        }

        let categories = (
            $tier_fixtures
            | each {|fixture| optional $fixture category "" }
            | uniq
            | sort
        )

        for category in $categories {
            let category_fixtures = (
                $tier_fixtures
                | where {|fixture| (optional $fixture category "") == $category }
            )

            let base = {
                tier: $tier
                category: $category
                total: ($category_fixtures | length)
                local_accept: (matrix-status-count $category_fixtures local accept)
                local_reject: (matrix-status-count $category_fixtures local reject)
                local_skip: (matrix-status-count $category_fixtures local skip)
                kernel_accept: (matrix-status-count $category_fixtures kernel accept)
                kernel_reject: (matrix-status-count $category_fixtures kernel reject)
                kernel_skip: (matrix-status-count $category_fixtures kernel skip)
                kernel_accept_versioned: (matrix-kernel-accept-versioned-count $category_fixtures true)
                kernel_accept_unversioned: (matrix-kernel-accept-versioned-count $category_fixtures false)
                kernel_accept_bounded: (matrix-kernel-accept-bounded-count $category_fixtures true)
                kernel_accept_unbounded: (matrix-kernel-accept-bounded-count $category_fixtures false)
                lane_host_safe: (matrix-test-lane-count $category_fixtures "host-safe")
                lane_host_gated: (matrix-test-lane-count $category_fixtures "host-gated")
                lane_dry_run: (matrix-test-lane-count $category_fixtures "dry-run")
                lane_vm_only: (matrix-test-lane-count $category_fixtures "vm-only")
            }

            let row = if $compat_kernel == null {
                $base
            } else {
                $base
                | upsert compat_kernel $compat_kernel
                | upsert kernel_accept_compatible (matrix-kernel-accept-compatible-count $category_fixtures true)
                | upsert kernel_accept_incompatible (matrix-kernel-accept-compatible-count $category_fixtures false)
                | upsert kernel_accept_requires_newer (matrix-kernel-accept-compat-reason-count $category_fixtures "kernel>=")
                | upsert kernel_accept_requires_older (matrix-kernel-accept-compat-reason-count $category_fixtures "kernel<")
            }

            $rows = ($rows | append $row)
        }
    }

    $rows
}

def print-fixture-matrix [fixtures compat_kernel] {
    for row in (fixture-matrix-rows $fixtures $compat_kernel) {
        print-fixture-matrix-row $row
    }
}

def print-fixture-matrix-from-derived [derived_fixtures compat_kernel] {
    for row in (fixture-matrix-rows-from-derived $derived_fixtures $compat_kernel) {
        print-fixture-matrix-row $row
    }
}

def print-fixture-matrix-row [row] {
    let compat_text = if (($row | get -o compat_kernel) == null) {
        ""
    } else {
        $" compat_kernel=($row.compat_kernel) kernel_accept_compatible=($row.kernel_accept_compatible) kernel_accept_incompatible=($row.kernel_accept_incompatible) kernel_accept_requires_newer=($row.kernel_accept_requires_newer) kernel_accept_requires_older=($row.kernel_accept_requires_older)"
    }
    print $"tier=($row.tier) category=($row.category) total=($row.total) local_accept=($row.local_accept) local_reject=($row.local_reject) local_skip=($row.local_skip) kernel_accept=($row.kernel_accept) kernel_reject=($row.kernel_reject) kernel_skip=($row.kernel_skip) kernel_accept_versioned=($row.kernel_accept_versioned) kernel_accept_unversioned=($row.kernel_accept_unversioned) kernel_accept_bounded=($row.kernel_accept_bounded) kernel_accept_unbounded=($row.kernel_accept_unbounded) lane_host_safe=($row.lane_host_safe) lane_host_gated=($row.lane_host_gated) lane_dry_run=($row.lane_dry_run) lane_vm_only=($row.lane_vm_only)($compat_text)"
}

def validate-tier-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in $VALID_TIERS {
        fail $"invalid ($label) tier '($value)'; expected one of ($VALID_TIERS | str join ', ')"
    }
}

def validate-test-lane-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in $VALID_TEST_LANES {
        fail $"invalid ($label) test lane '($value)'; expected one of ($VALID_TEST_LANES | str join ', ')"
    }
}

def validate-status-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in [accept reject skip] {
        fail $"invalid ($label) status '($value)'; expected accept, reject, or skip"
    }
}

def validate-host-features [fixture field: string] {
    for feature in (optional $fixture $field []) {
        if ($feature | str starts-with "tracepoint:") {
            continue
        }
        if ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) {
            let kfunc = ($feature | str substring ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC | str length)..)
            if $kfunc == "" {
                fail $"fixture ($fixture.name) declares empty ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) host feature in ($field)"
            }
            continue
        }
        if $feature not-in $VALID_HOST_FEATURES {
            fail $"fixture ($fixture.name) declares unknown ($field) feature '($feature)'; expected one of ($VALID_HOST_FEATURES | str join ', '), tracepoint:<system>/<event>, or ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC)<symbol>"
        }
    }
}

def validate-fixture-tags [fixture] {
    let tags = (optional $fixture tags [])
    for tag in $tags {
        if (($tag | describe) != "string") {
            fail $"fixture ($fixture.name) declares non-string tag value '($tag)'"
        }
        if ($tag | str trim) == "" {
            fail $"fixture ($fixture.name) declares an empty tag"
        }
    }

    for tag in ($tags | uniq) {
        let count = ($tags | where {|candidate| $candidate == $tag } | length)
        if $count > 1 {
            fail $"fixture ($fixture.name) declares duplicate tag '($tag)'"
        }
    }
}

def validate-kernel-feature-key-uniqueness [fixture_name: string origin: string features] {
    let keys = ($features | each {|feature| $feature | get -o key })

    for key in ($keys | uniq) {
        if $key == null or $key == "" {
            fail $"fixture ($fixture_name) ($origin) declares a kernel feature without key"
        }

        let count = ($keys | where {|candidate| $candidate == $key } | length)
        if $count > 1 {
            fail $"fixture ($fixture_name) ($origin) declares duplicate kernel feature key: ($key)"
        }
    }
}

def validate-kernel-feature-record [fixture_name: string origin: string feature] {
    let key = ($feature | get -o key)
    let min_kernel = ($feature | get -o min_kernel)
    let max_kernel = ($feature | get -o max_kernel_exclusive)
    let max_kernel_source = ($feature | get -o max_kernel_exclusive_source)
    let source = ($feature | get -o source)

    if $key == null or $key == "" {
        fail $"fixture ($fixture_name) ($origin) declares a kernel feature without key"
    }
    if $min_kernel == null or $min_kernel == "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) missing min_kernel"
    }
    if $source == null or $source == "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) missing source"
    }

    parse-kernel-version $min_kernel | ignore
    if $max_kernel != null and $max_kernel != "" {
        parse-kernel-version $max_kernel | ignore
        if $max_kernel_source == null or $max_kernel_source == "" {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) with max_kernel_exclusive=($max_kernel) missing max_kernel_exclusive_source"
        }
        if (kernel-version-compare $max_kernel $min_kernel) <= 0 {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) max_kernel_exclusive=($max_kernel) must be greater than min_kernel=($min_kernel)"
        }
    } else if $max_kernel_source != null and $max_kernel_source != "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) declares max_kernel_exclusive_source without max_kernel_exclusive"
    }
}

def validate-kernel-feature-metadata [fixture] {
    let features = (optional $fixture kernel_features [])
    let keys = ($features | each {|feature| $feature | get -o key })
    validate-kernel-feature-key-uniqueness $fixture.name "explicit kernel_features" $features

    for feature in $features {
        validate-kernel-feature-record $fixture.name "explicit kernel_features" $feature
    }

    for helper_name in (program-helper-names (fixture-program $fixture)) {
        let key = $"helper:($helper_name)"
        let known_feature = (helper-kernel-feature $helper_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls helper ($helper_name) without source-backed kernel metadata; add it to BPF_HELPER_IDS/HELPER_KERNEL_FEATURES or declare explicit kernel_features metadata"
        }
    }

    for kfunc_name in (program-kfunc-names (fixture-program $fixture)) {
        let key = $"kfunc:($kfunc_name)"
        let known_feature = (kfunc-kernel-feature $kfunc_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls kfunc ($kfunc_name) without source-backed kernel metadata; add it to KFUNC_KERNEL_FEATURES/KFUNC_KERNEL_FEATURE_FALLBACKS or declare explicit kernel_features metadata"
        }
    }

    let effective_features = (fixture-kernel-features $fixture)
    validate-kernel-feature-key-uniqueness $fixture.name "effective kernel_features" $effective_features
    for feature in $effective_features {
        validate-kernel-feature-record $fixture.name "effective kernel_features" $feature
    }

    $effective_features
}

def validate-kernel-feature-key-expectation [label: string expected_keys actual_keys] {
    let expected_keys = ($expected_keys | sort)
    let actual_keys = ($actual_keys | sort)
    let missing = ($expected_keys | where {|key| $key not-in $actual_keys })
    let unexpected = ($actual_keys | where {|key| $key not-in $expected_keys })

    if (($missing | length) > 0) or (($unexpected | length) > 0) {
        fail $"($label) drifted: missing=($missing | str join ',') unexpected=($unexpected | str join ',') actual=($actual_keys | str join ',')"
    }
}

def validate-program-target-kernel-feature-expectations [] {
    for expectation in $PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let actual_keys = (
            target-kernel-features $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"target-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-language-kernel-feature-expectations [] {
    for expectation in $PROGRAM_LANGUAGE_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-language-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-language-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-map-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-map-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-reserved-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_RESERVED_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-reserved-map-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-reserved-map-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-map-value-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_VALUE_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-map-value-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-map-value-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-global-kernel-feature-expectations [] {
    for expectation in $PROGRAM_GLOBAL_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-global-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-global-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-target-context-field-kernel-feature-expectations [] {
    for expectation in $TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let field = $expectation.field
        let expected = $expectation.feature
        let actual = (context-field-kernel-feature $field $target)

        if $actual == null {
            fail $"context-field-kernel-feature missing expected target-aware metadata for ($target) ctx.($field)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-field-kernel-feature drifted for ($target) ctx.($field): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-context-field-helper-kernel-feature-expectations [] {
    for expectation in $CONTEXT_FIELD_HELPER_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let field = $expectation.field
        let expected = $expectation.feature
        let actual = (context-field-helper-kernel-feature $field $target)

        if $actual == null {
            fail $"context-field-helper-kernel-feature missing expected metadata for ($target) ctx.($field)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-field-helper-kernel-feature drifted for ($target) ctx.($field): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-context-projection-kernel-feature-expectations [] {
    for expectation in $CONTEXT_PROJECTION_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let raw_access = $expectation.raw_access
        let expected = $expectation.feature
        let actual = (context-projection-kernel-feature $raw_access $target)

        if $actual == null {
            fail $"context-projection-kernel-feature missing expected metadata for ($target) ctx.($raw_access)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-projection-kernel-feature drifted for ($target) ctx.($raw_access): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-program-context-field-kernel-feature-expectations [] {
    for expectation in $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-context-field-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-context-field-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-surface-kernel-feature-expectations [] {
    for expectation in $PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-surface-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-surface-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-helper-kernel-feature-expectations [] {
    for expectation in $PROGRAM_HELPER_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-helper-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-helper-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-kfunc-kernel-feature-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-kfunc-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-kfunc-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-kfunc-kernel-feature-detail-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let expected = $expectation.feature
        let expected_key = $expected.key
        let matches = (
            program-kfunc-kernel-features $program $target
            | where {|feature| $feature.key == $expected_key }
        )

        if ($matches | is-empty) {
            fail $"program-kfunc-kernel-features for ($target) missing expected metadata for ($expected_key)"
        }

        let actual = ($matches | first)
        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"program-kfunc-kernel-features for ($target) ($expected_key) drifted: ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-program-callback-btf-kernel-feature-expectations [] {
    for expectation in $PROGRAM_CALLBACK_BTF_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-callback-btf-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-callback-btf-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-fixture-metadata [fixtures] {
    validate-program-target-kernel-feature-expectations
    validate-program-language-kernel-feature-expectations
    validate-program-map-kernel-feature-expectations
    validate-program-reserved-map-kernel-feature-expectations
    validate-program-map-value-kernel-feature-expectations
    validate-program-global-kernel-feature-expectations
    validate-target-context-field-kernel-feature-expectations
    validate-context-field-helper-kernel-feature-expectations
    validate-context-projection-kernel-feature-expectations
    validate-program-context-field-kernel-feature-expectations
    validate-program-surface-kernel-feature-expectations
    validate-program-helper-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-detail-expectations
    validate-program-callback-btf-kernel-feature-expectations

    let names = ($fixtures | each {|fixture| $fixture.name })

    for name in ($names | uniq) {
        let count = ($names | where {|candidate| $candidate == $name } | length)
        if $count > 1 {
            fail $"duplicate verifier fixture name: ($name)"
        }
    }

    mut derived = []

    for fixture in $fixtures {
        validate-tier-option $"fixture ($fixture.name)" ($fixture | get -o tier)
        validate-test-lane-option $"fixture ($fixture.name)" ($fixture | get -o default_test_lane)
        validate-status-option $"fixture ($fixture.name) local" $fixture.local
        validate-status-option $"fixture ($fixture.name) kernel" $fixture.kernel
        if $fixture.local != "accept" and $fixture.kernel != "skip" {
            fail $"fixture ($fixture.name) declares kernel=($fixture.kernel), but kernel checks only run after local accept; use kernel=skip for local ($fixture.local) fixtures"
        }
        validate-fixture-tags $fixture
        validate-host-features $fixture requires
        validate-host-features $fixture kernel_requires
        let kernel_features = (validate-kernel-feature-metadata $fixture)

        let min_kernel = ($fixture | get -o min_kernel)
        let min_kernel_source = ($fixture | get -o min_kernel_source)

        if $min_kernel != null and ($min_kernel_source == null or $min_kernel_source == "") {
            fail $"fixture ($fixture.name) declares min_kernel=($min_kernel) without min_kernel_source"
        }

        if $min_kernel == null and $min_kernel_source != null {
            fail $"fixture ($fixture.name) declares min_kernel_source without min_kernel"
        }

        if $min_kernel != null {
            parse-kernel-version $min_kernel | ignore
        }

        $derived = ($derived | append (fixture-derived-metadata $fixture $kernel_features))
    }

    $derived
}

def fixture-has-tag [fixture tag] {
    if $tag == null {
        return true
    }

    optional $fixture tags [] | any {|fixture_tag| $fixture_tag == $tag }
}

def fixture-matches-filters [fixture category tag tier exclude_tier local_status kernel_status test_lane] {
    (
        ($category == null or (optional $fixture category "") == $category)
        and (fixture-has-tag $fixture $tag)
        and ($tier == null or (fixture-tier $fixture) == $tier)
        and ($exclude_tier == null or (fixture-tier $fixture) != $exclude_tier)
        and ($local_status == null or $fixture.local == $local_status)
        and ($kernel_status == null or $fixture.kernel == $kernel_status)
        and ($test_lane == null or (fixture-default-test-lane $fixture) == $test_lane)
    )
}

def check-local-fixture [plugin_bin: string fixture] {
    let result = (run-nu-with-plugin-complete $plugin_bin (dry-run-describe-code $fixture))
    let stdout = ($result.stdout | str trim)
    let output = (combined-output $result)
    let accepted = ($result.exit_code == 0 and $stdout == "binary")
    let actual = if $accepted { "accept" } else { "reject" }

    if $actual != $fixture.local {
        fail $"fixture ($fixture.name) expected local ($fixture.local), got ($actual): ($output | str trim)"
    }

    let expected_fragment = ($fixture | get -o error_contains)
    if $fixture.local == "reject" and $expected_fragment != null and not ($output | str contains $expected_fragment) {
        fail $"fixture ($fixture.name) rejected, but error did not contain expected fragment: ($expected_fragment)"
    }

    { name: $fixture.name, local: $actual, output: $output }
}

def check-local-fixtures [plugin_bin: string fixtures jobs: int] {
    mut results = []

    for batch in ($fixtures | chunks $jobs) {
        let batch_results = if $jobs == 1 {
            $batch | each {|fixture| check-local-fixture $plugin_bin $fixture }
        } else {
            $batch | par-each --keep-order --threads $jobs {|fixture| check-local-fixture $plugin_bin $fixture }
        }

        for result in $batch_results {
            print $"local  ($result.local)  ($result.name)"
        }
        $results = ($results | append $batch_results)
    }

    $results
}

def kernel-preflight [] {
    mut reasons = []

    if not (command-exists bpftool) {
        $reasons = ($reasons | append "bpftool is not installed")
    }

    if not (is-root) {
        $reasons = ($reasons | append "not running as root")
    }

    if not ($BPFFS | path exists) {
        $reasons = ($reasons | append $"($BPFFS) does not exist")
    } else if (($BPFFS | path type) != "dir") {
        $reasons = ($reasons | append $"($BPFFS) is not a directory")
    } else if (command-exists findmnt) {
        let mount = (^findmnt -rn -T $BPFFS -o FSTYPE | complete)
        if $mount.exit_code != 0 {
            $reasons = ($reasons | append $"could not inspect ($BPFFS) mount type")
        } else if (($mount.stdout | str trim) != "bpf") {
            $reasons = ($reasons | append $"($BPFFS) is not mounted as bpffs")
        }
    }

    { available: (($reasons | length) == 0), reasons: $reasons }
}

def host-sys-enter-syscalls [] {
    let events_dir = "/sys/kernel/tracing/events/syscalls"
    if not ($events_dir | path exists) {
        fail $"($events_dir) does not exist; mount tracefs before checking host syscall tracepoint coverage"
    }
    if (($events_dir | path type) != "dir") {
        fail $"($events_dir) is not a directory"
    }

    ls $events_dir
    | where type == dir
    | get name
    | each {|path| $path | path basename }
    | where {|name| $name | str starts-with "sys_enter_" }
    | each {|name| $name | str replace "sys_enter_" "" }
    | sort
    | uniq
}

def modeled-sys-enter-syscalls [] {
    let tracepoint_rs = ([$REPO_ROOT "src" "kernel_btf" "tracepoint.rs"] | path join)
    mut in_list = false
    mut names = []

    for line in (open $tracepoint_rs | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "const WELL_KNOWN_SYS_ENTER_SYSCALLS: &[&str] = &[" {
            $in_list = true
            continue
        }
        if $in_list and $trimmed == "];" {
            break
        }
        if not $in_list {
            continue
        }

        let parsed = ($trimmed | parse --regex '^"(?P<name>[^"]+)",?$')
        if ($parsed | is-empty) {
            continue
        }

        $names = ($names | append ($parsed | first | get name))
    }

    if ($names | is-empty) {
        fail $"could not parse WELL_KNOWN_SYS_ENTER_SYSCALLS from ($tracepoint_rs)"
    }

    $names | sort | uniq
}

def check-host-syscall-tracepoint-coverage [] {
    let host = (host-sys-enter-syscalls)
    let modeled = (modeled-sys-enter-syscalls)
    let missing = ($host | where {|name| $name not-in $modeled })
    let extra = ($modeled | where {|name| $name not-in $host })

    if not ($missing | is-empty) {
        print "missing modeled sys_enter fallbacks for host tracepoints:"
        for name in $missing {
            print $"  ($name)"
        }
        fail $"($missing | length) host sys_enter tracepoint fallback gaps"
    }

    print $"ok: 0 host sys_enter tracepoint gaps; (($host | length)) host syscalls, (($modeled | length)) modeled fallbacks, (($extra | length)) modeled fallbacks not present on this host"
}

def host-feature-available [feature: string] {
    if $feature == "loopback-interface" {
        "/sys/class/net/lo" | path exists
    } else if $feature == "kernel-btf" {
        "/sys/kernel/btf/vmlinux" | path exists
    } else if ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) {
        let kfunc = ($feature | str substring ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC | str length)..)
        if $kfunc == "" or not ("/sys/kernel/btf/vmlinux" | path exists) or not (command-exists bpftool) {
            return false
        }
        let dump = (^bpftool btf dump file /sys/kernel/btf/vmlinux format raw | complete)
        if $dump.exit_code != 0 {
            return false
        }
        $dump.stdout | lines | any {|line| $line | str contains $"FUNC '($kfunc)'" }
    } else if $feature == "tracefs" {
        "/sys/kernel/tracing/events" | path exists
    } else if $feature == "cgroup-v2" {
        "/sys/fs/cgroup/cgroup.controllers" | path exists
    } else if $feature == "netns-self" {
        "/proc/self/ns/net" | path exists
    } else if $feature == "lirc-device" {
        "/dev/lirc0" | path exists
    } else if ($feature | str starts-with "tracepoint:") {
        let event = ($feature | str substring 11..)
        ("/sys/kernel/tracing/events" | path join $event) | path exists
    } else {
        false
    }
}

def fixture-missing-requirements [fixture] {
    optional $fixture requires []
    | where {|feature| not (host-feature-available $feature) }
}

def fixture-missing-kernel-requirements [fixture] {
    mut missing = (fixture-missing-requirements $fixture)

    let kernel_features = (
        optional $fixture kernel_requires []
        | where {|feature| not (host-feature-available $feature) }
    )
    $missing = ($missing | append $kernel_features)

    let min_kernel = (fixture-effective-min-kernel $fixture)
    if $min_kernel != null {
        let current = (current-kernel-release)
        if not (kernel-version-at-least $current $min_kernel) {
            $missing = ($missing | append $"kernel>=($min_kernel),current=($current)")
        }
    }
    let max_kernel = (fixture-effective-max-kernel-exclusive $fixture)
    if $max_kernel != null {
        let current = (current-kernel-release)
        if not (kernel-version-before $current $max_kernel) {
            $missing = ($missing | append $"kernel<($max_kernel),current=($current)")
        }
    }

    $missing
}

def write-dry-run-object [plugin_bin: string fixture obj_path: string] {
    let result = (run-nu-with-plugin-complete $plugin_bin (dry-run-save-code $fixture $obj_path))

    if $result.exit_code != 0 {
        fail $"fixture ($fixture.name) failed while writing dry-run object: ((combined-output $result) | str trim)"
    }
}

def bpftool-load [obj_path: string pin_path: string] {
    ^bpftool prog load $obj_path $pin_path | complete
}

def cleanup-pin [pin_path: string] {
    if ($pin_path | path exists) {
        try {
            rm -f $pin_path
        } catch { |_| null }
    }
}

def run-kernel-fixture [plugin_bin: string fixture tmp_dir: string] {
    if $fixture.kernel == "skip" {
        return { name: $fixture.name, kernel: "skip", reason: "fixture is local-only" }
    }

    let obj_path = ($tmp_dir | path join $"($fixture.name).o")
    let pin_path = ($BPFFS | path join $"nu_plugin_ebpf_verifier_diff_($fixture.name)_(random uuid)")

    write-dry-run-object $plugin_bin $fixture $obj_path

    let result = (bpftool-load $obj_path $pin_path)
    cleanup-pin $pin_path

    let actual = if $result.exit_code == 0 { "accept" } else { "reject" }
    if $actual != $fixture.kernel {
        fail $"fixture ($fixture.name) expected kernel ($fixture.kernel), got ($actual): ((combined-output $result) | str trim)"
    }

    let expected_fragment = ($fixture | get -o kernel_error_contains)
    let output = (combined-output $result)
    if $fixture.kernel == "reject" and $expected_fragment != null and not ($output | str contains $expected_fragment) {
        fail $"fixture ($fixture.name) kernel rejected, but log did not contain expected fragment: ($expected_fragment)"
    }

    { name: $fixture.name, kernel: $actual, output: (combined-output $result) }
}

def select-kernel-fixtures [fixtures require_kernel: bool] {
    select-fixtures-with-requirements $fixtures $require_kernel "kernel"
}

def select-fixtures-with-requirements [fixtures require_features: bool phase: string] {
    mut selected = []

    for fixture in $fixtures {
        let missing = if $phase == "kernel" {
            fixture-missing-kernel-requirements $fixture
        } else {
            fixture-missing-requirements $fixture
        }
        if (($missing | length) == 0) {
            $selected = ($selected | append $fixture)
        } else {
            let reason = ($missing | str join ",")
            if $require_features {
                fail $"fixture ($fixture.name) missing required host features: ($reason)"
            }
            print $"($phase) skip fixture ($fixture.name): missing ($reason)"
        }
    }

    $selected
}

def select-fixtures [fixture_names category tag tier exclude_tier local_status kernel_status test_lane] {
    validate-tier-option "selected" $tier
    validate-tier-option "excluded" $exclude_tier
    validate-test-lane-option "selected" $test_lane
    validate-status-option "local" $local_status
    validate-status-option "kernel" $kernel_status

    let fixtures = if $fixture_names == null {
        $FIXTURES
    } else {
        let missing = (
            $fixture_names
            | where {|fixture_name|
                not ($FIXTURES | any {|fixture| $fixture.name == $fixture_name })
            }
        )
        if (($missing | length) > 0) {
            fail $"unknown verifier fixtures: ($missing | str join ',')"
        }
        $FIXTURES | where {|fixture| $fixture.name in $fixture_names }
    }

    let selected = (
        $fixtures
        | where {|fixture| fixture-matches-filters $fixture $category $tag $tier $exclude_tier $local_status $kernel_status $test_lane }
    )

    if (($selected | length) == 0) {
        fail "no verifier fixtures matched the selected filters"
    }

    $selected
}

def has-explicit-fixture-selection [
    fixture
    fixtures
    category
    tag
    tier
    exclude_tier
    test_lane
    local_status
    kernel_status
    fast: bool
    smoke: bool
    full: bool
] {
    (
        $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
        or $fast
        or $smoke
        or $full
    )
}

def default-main-options [] {
    {
        help: false
        validate: false
        check_host_syscall_tracepoints: false
        list: false
        matrix: false
        json: false
        compat_kernel: null
        kernel: false
        no_kernel: false
        smoke: false
        fast: false
        full: false
        fixture: null
        fixtures: null
        category: null
        tag: null
        tier: null
        exclude_tier: null
        test_lane: null
        local_status: null
        kernel_status: null
        jobs: null
    }
}

def print-main-help [] {
    [
        "Usage:"
        "  > verifier_diff.nu {flags}"
        ""
        "Flags:"
        "  -h, --help: Display this help message"
        "  --validate: Validate fixture metadata and exit without resolving or running the plugin."
        "  --check-host-syscall-tracepoints: Compare this host's sys_enter tracepoints with modeled fallback coverage and exit."
        "  --list: List verifier fixtures and exit."
        "  --matrix: Print verifier fixture counts by tier and category, then exit."
        "  --json: Emit JSON for --list or --matrix."
        "  --compat-kernel <string>: With --list or --matrix, compare effective minimums against this kernel release."
        "  --kernel: Require kernel verifier checks instead of auto-skipping missing prerequisites."
        "  --no-kernel: Run only local dry-run compiler/VCC checks."
        "  --smoke: Run the default smoke lane: fast-tier, host-safe fixtures."
        "  --fast: Run only fixtures in the fast tier."
        "  --full: Run all fixtures when no narrower filter is selected."
        "  --fixture <string>: Run a fixture by exact name. May be repeated."
        "  --fixtures <list<string>>: Run one or more fixtures by exact name, for example --fixtures [a b]."
        "  --category <string>: Run fixtures with an exact category."
        "  --tag <string>: Run fixtures containing a tag."
        "  --tier <string>: Run fixtures in a tier: fast, btf, kernel, or vm-only."
        "  --exclude-tier <string>: Exclude fixtures in a tier: fast, btf, kernel, or vm-only."
        "  --test-lane <string>: Run fixtures in a default test lane: host-safe, host-gated, dry-run, or vm-only."
        "  --local-status <string>: Run fixtures whose expected local status is accept, reject, or skip."
        "  --kernel-status <string>: Run fixtures whose expected kernel status is accept, reject, or skip."
        "  --jobs <int>: Number of local fixture dry-run jobs. Defaults to VERIFIER_DIFF_JOBS or 4."
    ] | str join "\n" | print
}

def trim-surrounding-quotes [value: string] {
    let trimmed = ($value | str trim)
    if ($trimmed | str starts-with '"') and ($trimmed | str ends-with '"') {
        return ($trimmed | str replace -r '^"' "" | str replace -r '"$' "")
    }
    if ($trimmed | str starts-with "'") and ($trimmed | str ends-with "'") {
        return ($trimmed | str replace -r "^'" "" | str replace -r "'$" "")
    }

    $value
}

def flag-assignment [arg: string] {
    let parts = ($arg | split row "=")
    if (($parts | length) <= 1) {
        return { flag: $arg, has_value: false, value: null }
    }

    {
        flag: ($parts | first)
        has_value: true
        value: (trim-surrounding-quotes ($parts | skip 1 | str join "="))
    }
}

def require-flag-value [args idx: int flag: string] {
    let value_idx = ($idx + 1)
    if $value_idx >= ($args | length) {
        fail $"($flag) requires a value"
    }

    let value = ($args | get $value_idx)
    if (($value | describe) == "string") and ($value | str starts-with "--") {
        fail $"($flag) requires a value"
    }

    $value
}

def string-flag-value [value] {
    $value | into string
}

def fixture-flag-values [value] {
    if (($value | describe) | str starts-with "list") {
        return ($value | each {|item| $item | into string })
    }

    [($value | into string)]
}

def list-string-flag-value [flag: string value] {
    if (($value | describe) | str starts-with "list") {
        return ($value | each {|item| $item | into string })
    }

    if (($value | describe) == "string") and ($value | str starts-with "[") {
        let parsed = try {
            $value | from nuon
        } catch {
            null
        }

        if $parsed != null and (($parsed | describe) | str starts-with "list") {
            return ($parsed | each {|item| $item | into string })
        }

        if ($value | str ends-with "]") {
            let inner = (
                $value
                | str trim
                | str replace -r '^\[' ""
                | str replace -r '\]$' ""
            )
            let items = if ($inner | str contains ",") {
                $inner | split row ","
            } else {
                $inner | split row " "
            }
            let normalized = (
                $items
                | each {|item| $item | str trim }
                | where {|item| $item != "" }
            )

            if (($normalized | length) > 0) {
                return $normalized
            }
        }
    }

    fail $"($flag) expects a Nushell list, for example: ($flag) [fixture-a fixture-b]"
}

def int-flag-value [flag: string value] {
    if (($value | describe) == "int") {
        return $value
    }

    try {
        $value | into int
    } catch {
        fail $"($flag) expects an integer"
    }
}

def append-option-list [options key: string values] {
    let current = if ($options | get $key) == null { [] } else { $options | get $key }
    $options | upsert $key ($current | append $values)
}

def parse-main-args [args] {
    mut options = (default-main-options)
    mut i = 0
    while $i < ($args | length) {
        let raw_arg = ($args | get $i)
        if (($raw_arg | describe) != "string") {
            fail $"unexpected positional argument: ($raw_arg)"
        }

        let parsed = (flag-assignment $raw_arg)
        let arg = $parsed.flag
        let has_value = $parsed.has_value

        if $arg in ["-h" "--help"] {
            if $has_value {
                fail $"($arg) does not take a value"
            }
            $options = ($options | upsert help true)
            $i = ($i + 1)
        } else if $arg in ["--validate" "--check-host-syscall-tracepoints" "--list" "--matrix" "--json" "--kernel" "--no-kernel" "--smoke" "--fast" "--full"] {
            if $has_value {
                fail $"($arg) does not take a value"
            }

            let key = ($arg | str substring 2.. | str replace --all "-" "_")
            $options = ($options | upsert $key true)
            $i = ($i + 1)
        } else if $arg in ["--compat-kernel" "--category" "--tag" "--tier" "--exclude-tier" "--test-lane" "--local-status" "--kernel-status"] {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            let key = ($arg | str substring 2.. | str replace --all "-" "_")
            $options = ($options | upsert $key (string-flag-value $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else if $arg == "--fixture" {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            $options = (append-option-list $options fixture (fixture-flag-values $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else if $arg == "--fixtures" {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            $options = (append-option-list $options fixtures (list-string-flag-value $arg $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else if $arg == "--jobs" {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            $options = ($options | upsert jobs (int-flag-value $arg $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else {
            fail $"unknown argument: ($raw_arg)"
        }
    }

    $options
}

def --wrapped main [...args] {
    if (($env | get -o VERIFIER_DIFF_SOURCE_ONLY) == "1") {
        return
    }

    let options = (parse-main-args $args)
    if $options.help {
        print-main-help
        return
    }

    verifier-diff-main $options
}

def verifier-diff-main [options] {
    let validate = $options.validate
    let check_host_syscall_tracepoints = $options.check_host_syscall_tracepoints
    let list = $options.list
    let matrix = $options.matrix
    let json = $options.json
    let compat_kernel = $options.compat_kernel
    let kernel = $options.kernel
    let no_kernel = $options.no_kernel
    let smoke = $options.smoke
    let fast = $options.fast
    let full = $options.full
    let fixture = $options.fixture
    let fixtures = $options.fixtures
    let category = $options.category
    let tag = $options.tag
    let tier = $options.tier
    let exclude_tier = $options.exclude_tier
    let test_lane = $options.test_lane
    let local_status = $options.local_status
    let kernel_status = $options.kernel_status
    let jobs = $options.jobs

    if $kernel and $no_kernel {
        fail "--kernel and --no-kernel are mutually exclusive"
    }
    if $list and $matrix {
        fail "--list and --matrix are mutually exclusive"
    }
    if $validate and ($list or $matrix) {
        fail "--validate cannot be combined with --list or --matrix"
    }
    if $check_host_syscall_tracepoints and ($validate or $list or $matrix) {
        fail "--check-host-syscall-tracepoints cannot be combined with --validate, --list, or --matrix"
    }
    if $json and not ($list or $matrix) {
        fail "--json is only supported with --list or --matrix"
    }
    if $compat_kernel != null and not ($list or $matrix) {
        fail "--compat-kernel is only supported with --list or --matrix"
    }
    if $fast and $tier != null {
        fail "--fast and --tier are mutually exclusive"
    }
    if $fast and $exclude_tier != null {
        fail "--fast and --exclude-tier are mutually exclusive"
    }
    if $smoke and $fast {
        fail "--smoke and --fast are mutually exclusive"
    }
    if $smoke and $full {
        fail "--smoke and --full are mutually exclusive"
    }
    if $fast and $full {
        fail "--fast and --full are mutually exclusive"
    }
    if $smoke and $tier != null {
        fail "--smoke and --tier are mutually exclusive"
    }
    if $smoke and $exclude_tier != null {
        fail "--smoke and --exclude-tier are mutually exclusive"
    }
    if $smoke and $test_lane != null {
        fail "--smoke and --test-lane are mutually exclusive"
    }
    if $fixture != null and $fixtures != null {
        fail "--fixture and --fixtures are mutually exclusive"
    }

    if $check_host_syscall_tracepoints and (
        $kernel
        or $no_kernel
        or $smoke
        or $fast
        or $full
        or $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
    ) {
        fail "--check-host-syscall-tracepoints is a standalone host coverage audit and cannot be combined with fixture selection or run-mode flags"
    }

    if $validate and (
        $kernel
        or $no_kernel
        or $smoke
        or $fast
        or $full
        or $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
    ) {
        fail "--validate checks all fixture metadata and cannot be combined with fixture selection or run-mode flags"
    }

    if $validate {
        let _validated_fixtures = (validate-fixture-metadata $FIXTURES)
        print $"ok: (($FIXTURES | length)) verifier fixtures metadata-valid"
        return
    }

    if $check_host_syscall_tracepoints {
        check-host-syscall-tracepoint-coverage
        return
    }

    if $compat_kernel != null {
        parse-kernel-version $compat_kernel | ignore
    }

    let explicit_selection = (
        has-explicit-fixture-selection
            $fixture
            $fixtures
            $category
            $tag
            $tier
            $exclude_tier
            $test_lane
            $local_status
            $kernel_status
            $fast
            $smoke
            $full
    )
    let default_smoke = (not ($list or $matrix) and not $explicit_selection)
    let selected_tier = if ($smoke or $default_smoke or $fast) { "fast" } else { $tier }
    let selected_test_lane = if ($smoke or $default_smoke) { "host-safe" } else { $test_lane }
    let fixture_names = if $fixture == null { $fixtures } else { $fixture }
    let fixtures = (select-fixtures $fixture_names $category $tag $selected_tier $exclude_tier $local_status $kernel_status $selected_test_lane)
    let validated_fixtures = (validate-fixture-metadata $fixtures)

    if $list {
        let summaries = ($validated_fixtures | each {|fixture| fixture-summary-from-derived $fixture $compat_kernel })
        if $json {
            print ($summaries | to json)
            return
        }

        for summary in $summaries {
            let compat_text = if $compat_kernel == null {
                ""
            } else {
                $" compat_kernel=($summary.compat_kernel) compatible=($summary.compatible_with_compat_kernel) compat_reason=($summary.compat_kernel_reason)"
            }
            print $"($summary.name) target=($summary.target) local=($summary.local) kernel=($summary.kernel) category=($summary.category) tier=($summary.tier) default_test_lane=($summary.default_test_lane) requires=($summary.requires | str join ',') kernel_requires=($summary.kernel_requires | str join ',') effective_min_kernel=($summary.effective_min_kernel) effective_max_kernel_exclusive=($summary.effective_max_kernel_exclusive) kernel_features=(kernel-feature-labels $summary.kernel_features | str join ',') tags=($summary.tags | str join ',')($compat_text)"
        }
        return
    }
    if $matrix {
        if $json {
            print ((fixture-matrix-rows-from-derived $validated_fixtures $compat_kernel) | to json)
        } else {
            print-fixture-matrix-from-derived $validated_fixtures $compat_kernel
        }
        return
    }

    let local_jobs = (resolve-local-jobs $jobs)
    let plugin_bin = (resolve-plugin-bin $REPO_ROOT)
    print $"Using plugin: ($plugin_bin)"
    if $local_jobs > 1 {
        print $"Using local fixture jobs: ($local_jobs)"
    }
    if $default_smoke {
        print "Using default smoke lane: --tier fast --test-lane host-safe. Pass --full for the complete fixture sweep."
    }

    let local_fixtures = (select-fixtures-with-requirements $fixtures $kernel "local")
    if (($local_fixtures | length) == 0) {
        print "ok: 0 local fixtures"
        return
    }

    let local_results = (check-local-fixtures $plugin_bin $local_fixtures $local_jobs)

    let local_accepts = (
        $local_fixtures
        | zip $local_results
        | where {|pair| ($pair.1 | get local) == "accept" }
        | each {|pair| $pair.0 }
    )

    if $no_kernel {
        print $"ok: (($local_fixtures | length)) local fixtures, kernel checks disabled"
        return
    }

    let kernel_candidates = (
        $local_accepts
        | where {|fixture| $fixture.kernel != "skip" }
    )
    let kernel_fixtures = (select-kernel-fixtures $kernel_candidates $kernel)
    if (($kernel_fixtures | length) == 0) {
        print $"ok: (($local_fixtures | length)) local fixtures, no kernel fixtures"
        return
    }

    let preflight = (kernel-preflight)
    if not $preflight.available {
        let reason = ($preflight.reasons | str join "; ")
        if $kernel {
            fail $"kernel verifier checks requested but unavailable: ($reason)"
        }
        print $"kernel skip: ($reason)"
        print $"ok: (($local_fixtures | length)) local fixtures"
        return
    }

    let tmp_dir = (^mktemp -d | str trim)
    try {
        $kernel_fixtures
        | each {|fixture|
            let result = (run-kernel-fixture $plugin_bin $fixture $tmp_dir)
            print $"kernel ($result.kernel)  ($fixture.name)"
            $result
        }
        | ignore
        rm -rf $tmp_dir
    } catch { |err|
        try { rm -rf $tmp_dir } catch { |_| null }
        error make $err
    }

    print $"ok: (($local_fixtures | length)) local fixtures, (($kernel_fixtures | length)) kernel fixtures"
}
