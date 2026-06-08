
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
