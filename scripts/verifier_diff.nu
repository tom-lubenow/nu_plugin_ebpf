#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
const BPFFS = "/sys/fs/bpf"

const FIXTURES = [
    {
        name: "raw-tracepoint-count"
        target: "raw_tracepoint:sys_enter"
        program: '{|ctx| ($ctx.arg0 + $ctx.arg1) | count; 0 }'
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-packet-count"
        target: "xdp:lo"
        program: '{|ctx| $ctx.packet_len | count; "pass" }'
        local: "accept"
        kernel: "accept"
    }
    {
        name: "timer-start-rejects-non-map-timer"
        target: "raw_tracepoint:sys_enter"
        program: '{|| helper-call "bpf_timer_start" 0 1000 0 }'
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
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

def dry-run-describe-code [fixture] {
    let target = ($fixture.target | to nuon)
    $"ebpf attach --dry-run ($target) ($fixture.program) | describe"
}

def dry-run-save-code [fixture output_path: string] {
    let target = ($fixture.target | to nuon)
    let path = ($output_path | to nuon)
    $"ebpf attach --dry-run ($target) ($fixture.program) | save -f ($path)"
}

def combined-output [result] {
    $"($result.stdout)($result.stderr)"
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

    { name: $fixture.name, kernel: $actual, output: (combined-output $result) }
}

def select-fixtures [fixture_name] {
    if $fixture_name == null {
        $FIXTURES
    } else {
        let matches = ($FIXTURES | where {|fixture| $fixture.name == $fixture_name })
        if (($matches | length) == 0) {
            fail $"unknown verifier fixture: ($fixture_name)"
        }
        $matches
    }
}

def main [
    --kernel       # Require kernel verifier checks instead of auto-skipping missing prerequisites.
    --no-kernel    # Run only local dry-run compiler/VCC checks.
    --fixture: string # Run one fixture by exact name.
] {
    if $kernel and $no_kernel {
        fail "--kernel and --no-kernel are mutually exclusive"
    }

    let plugin_bin = (resolve-plugin-bin $REPO_ROOT)
    let fixtures = (select-fixtures $fixture)
    print $"Using plugin: ($plugin_bin)"

    let local_results = (
        $fixtures
        | each {|fixture|
            let result = (check-local-fixture $plugin_bin $fixture)
            print $"local  ($result.local)  ($fixture.name)"
            $result
        }
    )

    let local_accepts = (
        $fixtures
        | zip $local_results
        | where {|pair| ($pair.1 | get local) == "accept" }
        | each {|pair| $pair.0 }
    )

    if $no_kernel {
        print $"ok: (($fixtures | length)) local fixtures, kernel checks disabled"
        return
    }

    let kernel_fixtures = ($local_accepts | where {|fixture| $fixture.kernel != "skip" })
    if (($kernel_fixtures | length) == 0) {
        print $"ok: (($fixtures | length)) local fixtures, no kernel fixtures"
        return
    }

    let preflight = (kernel-preflight)
    if not $preflight.available {
        let reason = ($preflight.reasons | str join "; ")
        if $kernel {
            fail $"kernel verifier checks requested but unavailable: ($reason)"
        }
        print $"kernel skip: ($reason)"
        print $"ok: (($fixtures | length)) local fixtures"
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

    print $"ok: (($fixtures | length)) local fixtures, (($kernel_fixtures | length)) kernel fixtures"
}
