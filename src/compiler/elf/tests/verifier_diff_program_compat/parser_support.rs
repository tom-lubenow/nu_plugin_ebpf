use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierDiffFeatureRecord {
    pub(super) key: String,
    pub(super) min_kernel: String,
    pub(super) source: String,
    pub(super) max_kernel_exclusive: Option<String>,
    pub(super) max_kernel_exclusive_source: Option<String>,
}

pub(super) fn verifier_diff_const_body<'a>(
    source: &'a str,
    name: &str,
    delimiter: char,
) -> &'a str {
    let start_delimiter = format!("const {name} = {delimiter}");
    let start = source
        .find(&start_delimiter)
        .unwrap_or_else(|| panic!("expected scripts/verifier_diff.nu const {name}"))
        + start_delimiter.len();
    let end_delimiter = match delimiter {
        '[' => "\n]",
        '{' => "\n}",
        _ => panic!("unsupported verifier_diff.nu delimiter {delimiter}"),
    };
    let rest = &source[start..];
    let end = rest.find(end_delimiter).unwrap_or_else(|| {
        panic!("expected scripts/verifier_diff.nu const {name} to close with {end_delimiter:?}")
    });
    &rest[..end]
}

pub(super) fn verifier_diff_quoted_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("{field}: \"");
    let rest = verifier_diff_field_rest(text, &needle)?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

pub(super) fn verifier_diff_dollar_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("{field}: $");
    let rest = verifier_diff_field_rest(text, &needle)?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '}')
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn verifier_diff_field_rest<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(relative_index) = text[offset..].find(needle) {
        let index = offset + relative_index;
        let field_start = match text[..index].chars().next_back() {
            Some(c) => !(c == '_' || c.is_ascii_alphanumeric()),
            None => true,
        };
        if field_start {
            return Some(&text[index + needle.len()..]);
        }
        offset = index + 1;
    }
    None
}

pub(super) fn verifier_diff_feature_record(
    source: &str,
    const_name: &str,
) -> VerifierDiffFeatureRecord {
    let body = verifier_diff_const_body(source, const_name, '{');
    VerifierDiffFeatureRecord {
        key: verifier_diff_quoted_field(body, "key")
            .unwrap_or_else(|| panic!("{const_name} should declare key"))
            .to_string(),
        min_kernel: verifier_diff_quoted_field(body, "min_kernel")
            .unwrap_or_else(|| panic!("{const_name} should declare min_kernel"))
            .to_string(),
        source: verifier_diff_quoted_field(body, "source")
            .unwrap_or_else(|| panic!("{const_name} should declare source"))
            .to_string(),
        max_kernel_exclusive: verifier_diff_quoted_field(body, "max_kernel_exclusive")
            .map(str::to_string),
        max_kernel_exclusive_source: verifier_diff_quoted_field(
            body,
            "max_kernel_exclusive_source",
        )
        .map(str::to_string),
    }
}

pub(super) fn verifier_diff_program_feature_records(
    source: &str,
) -> BTreeMap<String, VerifierDiffFeatureRecord> {
    let end = source
        .find("const KERNEL_FEATURE_MAP_HASH")
        .expect("expected map kernel features to follow program kernel features");
    let program_feature_source = &source[..end];
    let mut records = BTreeMap::new();

    for line in program_feature_source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("const KERNEL_FEATURE_") {
            continue;
        }
        let const_name = trimmed
            .strip_prefix("const ")
            .and_then(|rest| rest.split_whitespace().next())
            .expect("kernel feature const declaration should expose its name");
        let record = verifier_diff_feature_record(source, const_name);
        assert!(
            records.insert(record.key.clone(), record).is_none(),
            "duplicate scripts/verifier_diff.nu program kernel feature key in {const_name}"
        );
    }

    records
}

pub(super) fn verifier_diff_feature_table_records(
    source: &str,
    const_name: &str,
    table_key_field: &str,
) -> BTreeMap<String, VerifierDiffFeatureRecord> {
    let body = verifier_diff_const_body(source, const_name, '[');
    let mut records = BTreeMap::new();

    for line in body.lines() {
        let Some(table_key) = verifier_diff_quoted_field(line, table_key_field) else {
            continue;
        };
        let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
            panic!("{const_name} entry {table_key} should reference a feature const")
        });
        let record = verifier_diff_feature_record(source, feature_const);
        assert!(
            records.insert(table_key.to_string(), record).is_none(),
            "duplicate scripts/verifier_diff.nu {const_name} entry for {table_key}"
        );
    }

    records
}

pub(super) fn verifier_diff_kfunc_fallback_records(
    source: &str,
) -> BTreeMap<String, VerifierDiffFeatureRecord> {
    let body = verifier_diff_const_body(source, "KFUNC_KERNEL_FEATURE_FALLBACKS", '[');
    let mut records = BTreeMap::new();

    for line in body.lines() {
        let Some(name) = verifier_diff_quoted_field(line, "name") else {
            continue;
        };
        let min_kernel = verifier_diff_quoted_field(line, "min_kernel").unwrap_or_else(|| {
            panic!("KFUNC_KERNEL_FEATURE_FALLBACKS entry {name} missing min_kernel")
        });
        let source = verifier_diff_quoted_field(line, "source").unwrap_or_else(|| {
            panic!("KFUNC_KERNEL_FEATURE_FALLBACKS entry {name} missing source")
        });
        let record = VerifierDiffFeatureRecord {
            key: format!("kfunc:{name}"),
            min_kernel: min_kernel.to_string(),
            source: source.to_string(),
            max_kernel_exclusive: verifier_diff_quoted_field(line, "max_kernel_exclusive")
                .map(str::to_string),
            max_kernel_exclusive_source: verifier_diff_quoted_field(
                line,
                "max_kernel_exclusive_source",
            )
            .map(str::to_string),
        };
        assert!(
            records.insert(name.to_string(), record).is_none(),
            "duplicate scripts/verifier_diff.nu KFUNC_KERNEL_FEATURE_FALLBACKS entry for {name}"
        );
    }

    records
}

#[derive(Debug, Clone)]
pub(super) struct VerifierDiffTargetContextFeatureRecord {
    pub(super) target: String,
    pub(super) field: String,
    pub(super) feature: VerifierDiffFeatureRecord,
}

pub(super) fn verifier_diff_target_context_field_feature_records(
    source: &str,
) -> Vec<VerifierDiffTargetContextFeatureRecord> {
    let body = verifier_diff_const_body(
        source,
        "TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS",
        '[',
    );
    let mut records = Vec::new();

    for line in body.lines() {
        let Some(target) = verifier_diff_quoted_field(line, "target") else {
            continue;
        };
        let field = verifier_diff_quoted_field(line, "field").unwrap_or_else(|| {
            panic!("TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS target {target} missing field")
        });
        let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
            panic!(
                "TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS target {target} field {field} should reference a feature const"
            )
        });

        records.push(VerifierDiffTargetContextFeatureRecord {
            target: target.to_string(),
            field: field.to_string(),
            feature: verifier_diff_feature_record(source, feature_const),
        });
    }

    records
}

pub(super) fn verifier_diff_tracepoint_field_feature_records(
    source: &str,
) -> Vec<VerifierDiffTargetContextFeatureRecord> {
    let body = verifier_diff_const_body(source, "TRACEPOINT_FIELD_KERNEL_FEATURES", '[');
    let mut records = Vec::new();

    for line in body.lines() {
        let Some(target) = verifier_diff_quoted_field(line, "target") else {
            continue;
        };
        let field = verifier_diff_quoted_field(line, "field").unwrap_or_else(|| {
            panic!("TRACEPOINT_FIELD_KERNEL_FEATURES target {target} missing field")
        });
        let feature_const = verifier_diff_dollar_field(line, "feature").unwrap_or_else(|| {
            panic!(
                "TRACEPOINT_FIELD_KERNEL_FEATURES target {target} field {field} should reference a feature const"
            )
        });

        records.push(VerifierDiffTargetContextFeatureRecord {
            target: target.to_string(),
            field: field.to_string(),
            feature: verifier_diff_feature_record(source, feature_const),
        });
    }

    records
}

pub(super) fn verifier_diff_quoted_strings(text: &str) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else {
            break;
        };
        values.insert(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    values
}

pub(super) fn verifier_diff_kernel_feature_default_lane_keys(
    source: &str,
    lane: &str,
) -> BTreeSet<String> {
    let body = source
        .split_once("def kernel-feature-default-test-lane [feature] {")
        .expect("expected kernel-feature-default-test-lane function")
        .1
        .split_once("\ndef fixture-default-test-lane")
        .expect("expected fixture-default-test-lane to follow kernel-feature-default-test-lane")
        .0;
    let needle = format!("return \"{lane}\"");
    let mut search_start = 0;

    while let Some(relative_return) = body[search_start..].find(&needle) {
        let return_index = search_start + relative_return;
        let before_return = &body[..return_index];
        if let Some(list_start) = before_return.rfind("if $key in [") {
            let list_with_return = &body[list_start..return_index];
            return verifier_diff_quoted_strings(list_with_return);
        }
        search_start = return_index + needle.len();
    }

    panic!("expected kernel-feature-default-test-lane to contain a {lane} key list")
}

pub(super) fn verifier_diff_program_target_expectations(
    source: &str,
) -> BTreeMap<String, BTreeSet<String>> {
    let body = verifier_diff_const_body(source, "PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS", '[');
    let mut expectations = BTreeMap::new();

    for line in body.lines() {
        let Some(target) = verifier_diff_quoted_field(line, "target") else {
            continue;
        };
        let feature_list = line
            .split_once("feature_keys: [")
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(list, _)| list)
            .unwrap_or_else(|| {
                panic!("PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS target {target} missing feature_keys")
            });
        let feature_keys = verifier_diff_quoted_strings(feature_list);
        assert!(
            expectations
                .insert(target.to_string(), feature_keys)
                .is_none(),
            "duplicate PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS target {target}"
        );
    }

    expectations
}
