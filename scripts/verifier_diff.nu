#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
const BPFFS = "/sys/fs/bpf"

const FIXTURES = [
    {
        name: "raw-tracepoint-count"
        category: "tracing"
        tags: [raw-tracepoint counter]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-count"
        category: "packet"
        tags: [xdp counter]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-put-get-null-checked"
        category: "maps"
        tags: [hash-map null-check]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash'
            '  let entry = (0 | map-get seen_args --kind hash)'
            '  if $entry != 0 {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "global-scalar-mut"
        category: "globals"
        tags: [data-global scalar]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = 0'
            '  $hits = ($hits + 1)'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-cgroup-array-contains"
        category: "packet"
        tags: [tc-action cgroup-array helper-policy]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-rejects-pid-context"
        category: "context-policy"
        tags: [xdp reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on xdp programs"
    }
    {
        name: "socket-filter-rejects-direct-data"
        category: "context-policy"
        tags: [socket-filter reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data is not available on socket_filter programs"
    }
    {
        name: "map-get-rejects-queue"
        category: "maps"
        tags: [queue reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-get q --kind queue'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get is not supported for map kind Queue"
    }
    {
        name: "timer-start-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{||'
            '  helper-call "bpf_timer_start" 0 1000 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "csum-diff-allows-null-zero-side"
        category: "helper-state"
        tags: [csum null-pointer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 0 0 0 0 | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "csum-diff-rejects-null-nonzero-side"
        category: "helper-state"
        tags: [csum null-pointer reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 4 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "csum-diff-rejects-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 2 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "redirect-neigh-allows-null-params"
        category: "helper-state"
        tags: [redirect-neigh null-pointer tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 0 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-neigh-rejects-null-nonzero-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 4 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "adjust-packet-xdp-head"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-xdp-ifindex"
        category: "language-surface"
        tags: [redirect xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-devmap"
        category: "language-surface"
        tags: [redirect-map xdp map]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-prog-array"
        category: "language-surface"
        tags: [tail-call prog-array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | tail-call jumps'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-sk-lookup-clear"
        category: "language-surface"
        tags: [assign-socket sk-lookup]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-apply"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockmap]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-sk-skb-parser-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]

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

def resolve-plugin-bin [repo_root: string] {
    let override = ($env | get -o PLUGIN_BIN)

    if $override != null {
        if (path-is-filelike $override) {
            $override
        } else {
            fail $"plugin binary not found: ($override)"
        }
    } else {
        newest-existing "plugin binary" [
            ($repo_root | path join target debug nu_plugin_ebpf)
            ($repo_root | path join target release nu_plugin_ebpf)
        ]
    }
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

def run-nu-with-plugin-complete [plugin_bin: string code: string] {
    run-external (current-nu-bin) "--plugins" $"[($plugin_bin)]" "-c" $code | complete
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

def fixture-summary [fixture] {
    {
        name: $fixture.name
        category: (optional $fixture category "")
        local: $fixture.local
        kernel: $fixture.kernel
        requires: ((optional $fixture requires []) | str join ",")
        tags: ((optional $fixture tags []) | str join ",")
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

def fixture-has-tag [fixture tag] {
    if $tag == null {
        return true
    }

    optional $fixture tags [] | any {|fixture_tag| $fixture_tag == $tag }
}

def fixture-matches-filters [fixture category tag local_status kernel_status] {
    (
        ($category == null or (optional $fixture category "") == $category)
        and (fixture-has-tag $fixture $tag)
        and ($local_status == null or $fixture.local == $local_status)
        and ($kernel_status == null or $fixture.kernel == $kernel_status)
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

def host-feature-available [feature: string] {
    if $feature == "loopback-interface" {
        "/sys/class/net/lo" | path exists
    } else if $feature == "kernel-btf" {
        "/sys/kernel/btf/vmlinux" | path exists
    } else if $feature == "cgroup-v2" {
        "/sys/fs/cgroup" | path exists
    } else if $feature == "netns-self" {
        "/proc/self/ns/net" | path exists
    } else {
        false
    }
}

def fixture-missing-requirements [fixture] {
    optional $fixture requires []
    | where {|feature| not (host-feature-available $feature) }
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
        let missing = (fixture-missing-requirements $fixture)
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

def select-fixtures [fixture_name category tag local_status kernel_status] {
    validate-status-option "local" $local_status
    validate-status-option "kernel" $kernel_status

    let fixtures = if $fixture_name == null {
        $FIXTURES
    } else {
        let matches = ($FIXTURES | where {|fixture| $fixture.name == $fixture_name })
        if (($matches | length) == 0) {
            fail $"unknown verifier fixture: ($fixture_name)"
        }
        $matches
    }

    let selected = (
        $fixtures
        | where {|fixture| fixture-matches-filters $fixture $category $tag $local_status $kernel_status }
    )

    if (($selected | length) == 0) {
        fail "no verifier fixtures matched the selected filters"
    }

    $selected
}

def main [
    --list         # List verifier fixtures and exit.
    --kernel       # Require kernel verifier checks instead of auto-skipping missing prerequisites.
    --no-kernel    # Run only local dry-run compiler/VCC checks.
    --fixture: string # Run one fixture by exact name.
    --category: string # Run fixtures with an exact category.
    --tag: string # Run fixtures containing a tag.
    --local-status: string # Run fixtures whose expected local status is accept, reject, or skip.
    --kernel-status: string # Run fixtures whose expected kernel status is accept, reject, or skip.
] {
    if $kernel and $no_kernel {
        fail "--kernel and --no-kernel are mutually exclusive"
    }

    let fixtures = (select-fixtures $fixture $category $tag $local_status $kernel_status)

    if $list {
        for fixture in $fixtures {
            let summary = (fixture-summary $fixture)
            print $"($summary.name) local=($summary.local) kernel=($summary.kernel) category=($summary.category) requires=($summary.requires) tags=($summary.tags)"
        }
        return
    }

    let plugin_bin = (resolve-plugin-bin $REPO_ROOT)
    print $"Using plugin: ($plugin_bin)"

    let local_fixtures = (select-fixtures-with-requirements $fixtures $kernel "local")
    if (($local_fixtures | length) == 0) {
        print "ok: 0 local fixtures"
        return
    }

    let local_results = (
        $local_fixtures
        | each {|fixture|
            let result = (check-local-fixture $plugin_bin $fixture)
            print $"local  ($result.local)  ($fixture.name)"
            $result
        }
    )

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
