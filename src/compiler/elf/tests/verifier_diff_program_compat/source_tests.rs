use super::*;

fn modeled_kfunc_signature_names(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter(|line| line.contains("=> Some(Self"))
        .flat_map(verifier_diff_quoted_strings)
        .filter(|name| name.starts_with("bpf_") || name.starts_with("scx_"))
        .collect()
}

fn verifier_diff_kfunc_call_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = source;
    let marker = "kfunc-call \"";

    while let Some(start) = rest.find(marker) {
        rest = &rest[start + marker.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        names.insert(rest[..end].to_string());
        rest = &rest[end + 1..];
    }

    names
}

fn modeled_helper_names(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter(|line| line.contains("=> \"bpf_"))
        .flat_map(verifier_diff_quoted_strings)
        .filter(|name| name.starts_with("bpf_"))
        .collect()
}

fn verifier_diff_helper_call_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = source;
    let marker = "helper-call \"";

    while let Some(start) = rest.find(marker) {
        rest = &rest[start + marker.len()..];
        let Some(end) = rest.find('"') else {
            break;
        };
        names.insert(rest[..end].to_string());
        rest = &rest[end + 1..];
    }

    names
}

#[test]
fn test_verifier_diff_source_fixtures_cover_modeled_kfunc_signatures() {
    let signature_source = include_str!("../../../instruction/kfunc_signature.rs");
    let verifier_diff = verifier_diff_source_with_fixtures();

    let modeled = modeled_kfunc_signature_names(signature_source);
    let fixture_calls = verifier_diff_kfunc_call_names(&verifier_diff);
    let missing = modeled
        .difference(&fixture_calls)
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "scripts/verifier_diff.nu source fixtures are missing modeled kfunc-call coverage for: {}",
        missing.join(", ")
    );
}

#[test]
fn test_verifier_diff_source_fixtures_cover_modeled_helper_names() {
    let instruction_source = include_str!("../../../instruction.rs");
    let verifier_diff = verifier_diff_source_with_fixtures();

    let modeled = modeled_helper_names(instruction_source);
    let fixture_calls = verifier_diff_helper_call_names(&verifier_diff);
    let pending = BTreeSet::<String>::new();

    let missing = modeled
        .difference(&fixture_calls)
        .filter(|name| !pending.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let stale_pending = pending
        .difference(&modeled)
        .chain(pending.intersection(&fixture_calls))
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "scripts/verifier_diff.nu source fixtures are missing modeled helper-call coverage for: {}",
        missing.join(", ")
    );
    assert!(
        stale_pending.is_empty(),
        "verifier_diff helper-call pending coverage entries are stale or now covered: {}",
        stale_pending.join(", ")
    );
}
