
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
        validate_fixture_file: null
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
        "  --validate-fixture-file <path>: Validate one fixture chunk file and exit without resolving or running the plugin."
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
        } else if $arg in ["--validate-fixture-file" "--compat-kernel" "--category" "--tag" "--tier" "--exclude-tier" "--test-lane" "--local-status" "--kernel-status"] {
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
