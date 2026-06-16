def verifier-diff-fixture-chunk-paths [] {
    glob ($VERIFIER_DIFF_FIXTURE_CHUNKS_DIR | path join "fixtures_*.nu") | sort
}

def fixture-chunk-line-count [path: path] {
    open --raw $path | lines | length
}

def fixture-status-count-from-raw [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def fixture-values-from-raw [fixtures field: string default] {
    $fixtures
    | each {|fixture| optional $fixture $field $default }
    | uniq
    | sort
}

def fixture-has-chunk-index-tag [fixture tag] {
    if $tag == null {
        return true
    }

    optional $fixture tags [] | any {|fixture_tag| $fixture_tag == $tag }
}

def fixture-matches-chunk-index-filters [
    fixture
    fixture_names
    category
    tag
    tier
    exclude_tier
    local_status
    kernel_status
    test_lane
    gap_only: bool
] {
    let fixture_tier = (fixture-tier $fixture)
    let declared_test_lane = (optional $fixture default_test_lane "")

    (
        ($fixture_names == null or $fixture.name in $fixture_names)
        and ($category == null or (optional $fixture category "") == $category)
        and (fixture-has-chunk-index-tag $fixture $tag)
        and ($tier == null or $fixture_tier == $tier)
        and ($exclude_tier == null or $fixture_tier != $exclude_tier)
        and ($local_status == null or $fixture.local == $local_status)
        and ($kernel_status == null or $fixture.kernel == $kernel_status)
        and ($test_lane == null or $declared_test_lane == $test_lane)
        and (not $gap_only or ($fixture.local == "accept" and $fixture.kernel == "skip"))
    )
}

def fixture-chunk-index-row [
    path: path
    fixture_names
    category
    tag
    tier
    exclude_tier
    local_status
    kernel_status
    test_lane
    gap_only: bool
] {
    let fixtures = (parse-verifier-diff-fixture-chunk $path)
    let selected = (
        $fixtures
        | where {|fixture|
            (fixture-matches-chunk-index-filters
                $fixture
                $fixture_names
                $category
                $tag
                $tier
                $exclude_tier
                $local_status
                $kernel_status
                $test_lane
                $gap_only)
        }
    )
    let selected_names = ($selected | get name)

    {
        file: ($path | path basename)
        line_count: (fixture-chunk-line-count $path)
        total: ($fixtures | length)
        selected: ($selected | length)
        categories: (fixture-values-from-raw $selected category "")
        tiers: ($selected | each {|fixture| fixture-tier $fixture } | uniq | sort)
        declared_test_lanes: (fixture-values-from-raw $selected default_test_lane "auto")
        local_accept: (fixture-status-count-from-raw $selected local accept)
        local_reject: (fixture-status-count-from-raw $selected local reject)
        local_skip: (fixture-status-count-from-raw $selected local skip)
        kernel_accept: (fixture-status-count-from-raw $selected kernel accept)
        kernel_reject: (fixture-status-count-from-raw $selected kernel reject)
        kernel_skip: (fixture-status-count-from-raw $selected kernel skip)
        first_fixture: (if ($selected_names | is-empty) { "" } else { $selected_names | first })
        last_fixture: (if ($selected_names | is-empty) { "" } else { $selected_names | last })
    }
}

def has-chunk-index-filter [
    fixture_names
    category
    tag
    tier
    exclude_tier
    local_status
    kernel_status
    test_lane
    gap_only: bool
] {
    (
        $fixture_names != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $local_status != null
        or $kernel_status != null
        or $test_lane != null
        or $gap_only
    )
}

def validate-chunk-index-fixture-names [fixture_names] {
    if $fixture_names == null {
        return
    }

    let missing = (
        $fixture_names
        | where {|fixture_name|
            not ($FIXTURES | any {|fixture| $fixture.name == $fixture_name })
        }
    )
    if (($missing | length) > 0) {
        fail $"unknown verifier fixtures: ($missing | str join ',')"
    }
}

def fixture-chunk-index-rows [
    fixture_names
    category
    tag
    tier
    exclude_tier
    local_status
    kernel_status
    test_lane
    gap_only: bool
] {
    validate-tier-option "selected" $tier
    validate-tier-option "excluded" $exclude_tier
    validate-test-lane-option "selected" $test_lane
    validate-status-option "local" $local_status
    validate-status-option "kernel" $kernel_status
    if $test_lane != null {
        fail "--chunks does not support derived --test-lane filters; use --list or --matrix for default lane views"
    }
    validate-chunk-index-fixture-names $fixture_names

    let rows = (
        verifier-diff-fixture-chunk-paths
        | each {|path|
            (fixture-chunk-index-row
                $path
                $fixture_names
                $category
                $tag
                $tier
                $exclude_tier
                $local_status
                $kernel_status
                $test_lane
                $gap_only)
        }
    )

    let filtered = if (has-chunk-index-filter $fixture_names $category $tag $tier $exclude_tier $local_status $kernel_status $test_lane $gap_only) {
        $rows | where {|row| $row.selected > 0 }
    } else {
        $rows
    }
    if (($filtered | length) == 0) {
        fail "no verifier fixtures matched the selected filters"
    }

    $filtered
}

def chunk-index-field-sum [rows field: string] {
    $rows
    | reduce --fold 0 {|row, acc| $acc + ($row | get $field) }
}

def chunk-index-list-union [rows field: string] {
    $rows
    | reduce --fold [] {|row, acc| $acc | append ($row | get $field) }
    | where {|value| $value != "" }
    | uniq
    | sort
}

def fixture-chunk-index-summary [rows] {
    {
        chunks: ($rows | length)
        line_count: (chunk-index-field-sum $rows line_count)
        total: (chunk-index-field-sum $rows total)
        selected: (chunk-index-field-sum $rows selected)
        categories: (chunk-index-list-union $rows categories)
        tiers: (chunk-index-list-union $rows tiers)
        declared_test_lanes: (chunk-index-list-union $rows declared_test_lanes)
        local_accept: (chunk-index-field-sum $rows local_accept)
        local_reject: (chunk-index-field-sum $rows local_reject)
        local_skip: (chunk-index-field-sum $rows local_skip)
        kernel_accept: (chunk-index-field-sum $rows kernel_accept)
        kernel_reject: (chunk-index-field-sum $rows kernel_reject)
        kernel_skip: (chunk-index-field-sum $rows kernel_skip)
    }
}

def print-fixture-chunk-index [rows] {
    for row in $rows {
        print $"chunk=($row.file) lines=($row.line_count) total=($row.total) selected=($row.selected) categories=($row.categories | str join ',') tiers=($row.tiers | str join ',') declared_lanes=($row.declared_test_lanes | str join ',') local=($row.local_accept)/($row.local_reject)/($row.local_skip) kernel=($row.kernel_accept)/($row.kernel_reject)/($row.kernel_skip) first=($row.first_fixture) last=($row.last_fixture)"
    }
    let summary = (fixture-chunk-index-summary $rows)
    print $"summary chunks=($summary.chunks) lines=($summary.line_count) total=($summary.total) selected=($summary.selected) categories=($summary.categories | str join ',') tiers=($summary.tiers | str join ',') declared_lanes=($summary.declared_test_lanes | str join ',') local=($summary.local_accept)/($summary.local_reject)/($summary.local_skip) kernel=($summary.kernel_accept)/($summary.kernel_reject)/($summary.kernel_skip)"
}
