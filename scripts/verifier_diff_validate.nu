#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
const MAX_VERIFIER_FIXTURE_CHUNK_LINES = 640
source ($REPO_ROOT | path join scripts verifier_diff metadata core_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata tracepoint_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata context_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff metadata expectations.nu)

source ($REPO_ROOT | path join scripts verifier_diff fixtures.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime core.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime source_text.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_fields.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime tracepoint_field_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_source_parsing.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_roots.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_function_roots.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_projection_alias_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_projection_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime context_projection_get_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime program_target_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime program_features.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime matrix_validation.nu)
source ($REPO_ROOT | path join scripts verifier_diff runtime expectation_validation.nu)

def validate-default-options [] {
    {
        help: false
        fixture_file: null
        fixture: null
    }
}

def print-validate-help [] {
    [
        "Usage:"
        "  > verifier_diff_validate.nu {flags}"
        ""
        "Flags:"
        "  -h, --help: Display this help message"
        "  --fixture-file <path>: Validate only fixtures loaded from one fixture chunk file."
        "  --fixture <string>: Validate one fixture by exact name. May be repeated."
        ""
        "Full validation also checks global feature-expectation metadata and fixture chunk sizes."
    ] | str join "\n" | print
}

def validate-require-flag-value [args idx: int flag: string] {
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

def append-validate-option-list [options key: string value] {
    let current = if ($options | get $key) == null { [] } else { $options | get $key }
    $options | upsert $key ($current | append [($value | into string)])
}

def parse-validate-args [args] {
    mut options = (validate-default-options)
    mut i = 0
    while $i < ($args | length) {
        let raw_arg = ($args | get $i)
        if (($raw_arg | describe) != "string") {
            fail $"unexpected positional argument: ($raw_arg)"
        }

        if $raw_arg in ["-h" "--help"] {
            $options = ($options | upsert help true)
            $i = ($i + 1)
        } else if $raw_arg == "--fixture-file" {
            let value = (validate-require-flag-value $args $i $raw_arg)
            $options = ($options | upsert fixture_file ($value | into string))
            $i = ($i + 2)
        } else if $raw_arg == "--fixture" {
            let value = (validate-require-flag-value $args $i $raw_arg)
            $options = (append-validate-option-list $options fixture $value)
            $i = ($i + 2)
        } else {
            fail $"unknown argument: ($raw_arg)"
        }
    }

    $options
}

def selected-fixtures-for-validation [options] {
    let base = if $options.fixture_file == null {
        $FIXTURES
    } else {
        parse-verifier-diff-fixture-chunk $options.fixture_file
    }

    if $options.fixture == null {
        return $base
    }

    let selected = ($base | where {|fixture| $fixture.name in $options.fixture })
    let found_names = ($selected | get name)
    let missing = (
        $options.fixture
        | where {|name| $name not-in $found_names }
    )
    if (($missing | length) > 0) {
        fail $"unknown verifier fixture names: ($missing | str join ', ')"
    }

    $selected
}

def validate-fixture-chunk-size [path: path] {
    let line_count = (open --raw $path | lines | length)
    if $line_count > $MAX_VERIFIER_FIXTURE_CHUNK_LINES {
        fail $"verifier fixture chunk ($path) has ($line_count) lines; split it below ($MAX_VERIFIER_FIXTURE_CHUNK_LINES) lines before adding more fixtures"
    }
}

def validate-fixture-chunk-sizes [options] {
    let paths = if $options.fixture_file != null {
        [$options.fixture_file]
    } else if $options.fixture == null {
        glob ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join "fixtures_*.nu") | sort
    } else {
        []
    }

    for path in $paths {
        validate-fixture-chunk-size $path
    }
}

def --wrapped main [...args] {
    let options = (parse-validate-args $args)
    if $options.help {
        print-validate-help
        return
    }

    validate-fixture-chunk-sizes $options
    if $options.fixture_file == null and $options.fixture == null {
        validate-verifier-feature-expectations
    }
    let fixtures = (selected-fixtures-for-validation $options)
    let _validated_fixtures = (validate-fixture-metadata $fixtures)
    print $"ok: (($fixtures | length)) verifier fixtures metadata-valid"
}
