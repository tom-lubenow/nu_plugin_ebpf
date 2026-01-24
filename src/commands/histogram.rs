//! Display histogram values from the `histogram` command

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Signature, SyntaxShape, Type, Value, record,
};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct EbpfHistogram;

impl PluginCommand for EbpfHistogram {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf histogram"
    }

    fn description(&self) -> &str {
        "Display histogram values collected by the histogram command in an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Reads the histogram map from an attached probe that uses the `histogram` command.
Each row shows a log2 bucket range and the count of values in that bucket.

For latency histograms (from stop-timer), use --ns to display ranges
as human-readable durations (ns, us, ms, s).

Example workflow:
  ebpf attach --pin lat 'kprobe:sys_read' {|ctx| start-timer }
  let id = ebpf attach --pin lat 'kretprobe:sys_read' {|ctx| stop-timer | histogram }
  sleep 5sec
  ebpf histogram $id --ns"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf histogram")
            .required("id", SyntaxShape::Int, "Probe ID to get histogram from")
            .switch("ns", "Show ranges as human-readable durations", None)
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "let id = ebpf attach 'kretprobe:sys_read' {|ctx| stop-timer | histogram }; sleep 5sec; ebpf histogram $id",
                description: "Collect and display latency histogram for sys_read",
                result: None,
            },
            Example {
                example: "ebpf histogram $id --ns",
                description: "Show histogram with human-readable nanosecond ranges",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _plugin: &EbpfPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(super::linux_only_error(call.head));
        }

        #[cfg(target_os = "linux")]
        {
            run_histogram(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_histogram(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    use crate::loader::get_state;

    let id: i64 = call.req(0)?;
    let id = super::validate_probe_id(id, call.head)?;
    let as_ns = call.has_flag("ns")?;
    let span = call.head;

    let state = get_state();
    let entries = state.get_histogram(id).map_err(|e| {
        LabeledError::new("Failed to get histogram").with_label(e.to_string(), span)
    })?;

    if entries.is_empty() {
        return Ok(PipelineData::Value(Value::list(vec![], span), None));
    }

    let max_count = entries.iter().map(|e| e.count).max().unwrap_or(1);
    let bar_width = 40;

    let records: Vec<Value> = entries
        .into_iter()
        .map(|entry| {
            let (low, high) = bucket_range(entry.bucket);

            let range_str = if as_ns {
                if entry.bucket == 0 {
                    "0".to_string()
                } else {
                    format!("{} - {}", format_ns(low), format_ns(high))
                }
            } else if entry.bucket == 0 {
                "0".to_string()
            } else {
                format!("{} - {}", low, high)
            };

            let bar_len = ((entry.count as f64 / max_count as f64) * bar_width as f64) as usize;
            let bar = "#".repeat(bar_len.max(1));

            Value::record(
                record! {
                    "bucket" => Value::int(entry.bucket, span),
                    "range" => Value::string(range_str, span),
                    "count" => Value::int(entry.count, span),
                    "bar" => Value::string(bar, span),
                },
                span,
            )
        })
        .collect();

    Ok(PipelineData::Value(Value::list(records, span), None))
}

#[cfg(target_os = "linux")]
fn format_ns(ns: i64) -> String {
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{}us", ns / 1_000)
    } else if ns < 1_000_000_000 {
        format!("{}ms", ns / 1_000_000)
    } else {
        format!("{:.1}s", ns as f64 / 1_000_000_000.0)
    }
}

#[cfg(target_os = "linux")]
fn bucket_range(bucket: i64) -> (i64, i64) {
    if bucket == 0 {
        (0, 0)
    } else {
        let low = 1i64 << (bucket - 1);
        let high = (1i64 << bucket) - 1;
        (low, high)
    }
}
