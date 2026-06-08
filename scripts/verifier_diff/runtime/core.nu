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
