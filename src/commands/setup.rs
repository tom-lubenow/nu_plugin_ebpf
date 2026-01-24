//! `ebpf setup` command - configure capabilities for non-root usage

use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    Category, Example, LabeledError, PipelineData, Record, Signature, Type, Value,
};

use crate::EbpfPlugin;

#[derive(Clone)]
pub struct EbpfSetup;

impl PluginCommand for EbpfSetup {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "ebpf setup"
    }

    fn description(&self) -> &str {
        "Configure Linux capabilities for running eBPF without sudo."
    }

    fn extra_description(&self) -> &str {
        r#"This command checks system configuration and shows how to enable eBPF
without running as root.

Required capabilities:
  - CAP_BPF: Load and run BPF programs
  - CAP_PERFMON: Attach to perf events (kprobes, uprobes, tracepoints)

Required kernel setting:
  - perf_event_paranoid <= 2: Allow unprivileged perf event access

The command shows the commands needed to configure your system.
After setup, you can use 'ebpf attach' without sudo.

Note: File capabilities are cleared when the binary is modified (e.g., after
recompilation), so you'll need to run setup again after updates."#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf setup")
            .input_output_types(vec![(Type::Nothing, Type::record())])
            .switch(
                "check",
                "Check current configuration status without making changes",
                Some('c'),
            )
            .category(Category::Experimental)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["capabilities", "cap_bpf", "permissions", "root", "sudo"]
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf setup",
                description: "Show the commands needed to enable eBPF without sudo",
                result: None,
            },
            Example {
                example: "ebpf setup --check",
                description: "Check if system is already configured",
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
            run_setup(call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_setup(call: &EvaluatedCall) -> Result<PipelineData, LabeledError> {
    let check_only = call.has_flag("check")?;
    let span = call.head;

    // Get the path to the plugin binary
    let plugin_path = std::env::current_exe().map_err(|e| {
        LabeledError::new("Failed to determine plugin path")
            .with_label(e.to_string(), span)
    })?;

    let plugin_path_str = plugin_path.display().to_string();

    // Check current capabilities
    let current_caps = get_file_capabilities(&plugin_path_str);
    let has_bpf = current_caps.contains("cap_bpf");
    let has_perfmon = current_caps.contains("cap_perfmon");
    let caps_configured = has_bpf && has_perfmon;

    // Check perf_event_paranoid
    let paranoid_level = get_perf_event_paranoid();
    let paranoid_ok = paranoid_level <= 2;

    // Overall status
    let is_ready = caps_configured && paranoid_ok;

    if check_only {
        let mut rec = Record::new();
        rec.push("plugin_path", Value::string(&plugin_path_str, span));
        rec.push("cap_bpf", Value::bool(has_bpf, span));
        rec.push("cap_perfmon", Value::bool(has_perfmon, span));
        rec.push("caps_configured", Value::bool(caps_configured, span));
        rec.push("perf_event_paranoid", Value::int(paranoid_level as i64, span));
        rec.push("paranoid_ok", Value::bool(paranoid_ok, span));
        rec.push("ready", Value::bool(is_ready, span));
        if !current_caps.is_empty() {
            rec.push("current_caps", Value::string(&current_caps, span));
        }

        return Ok(PipelineData::Value(Value::record(rec, span), None));
    }

    // Generate setup commands
    let setcap_cmd = format!(
        "sudo setcap cap_bpf,cap_perfmon+ep '{}'",
        plugin_path_str.replace('\'', "'\\''")
    );

    let mut rec = Record::new();
    rec.push("plugin_path", Value::string(&plugin_path_str, span));
    rec.push("ready", Value::bool(is_ready, span));

    // Build commands list
    let mut commands = Vec::new();
    if !caps_configured {
        commands.push(Value::string(&setcap_cmd, span));
    }
    if !paranoid_ok {
        commands.push(Value::string(
            "sudo sysctl kernel.perf_event_paranoid=2",
            span,
        ));
    }

    if commands.is_empty() {
        rec.push(
            "message",
            Value::string("System is configured. eBPF should work without sudo.", span),
        );
    } else {
        rec.push("commands", Value::list(commands, span));

        let mut issues = Vec::new();
        if !caps_configured {
            issues.push("capabilities not set");
        }
        if !paranoid_ok {
            issues.push(
                if paranoid_level > 2 {
                    "perf_event_paranoid too restrictive"
                } else {
                    "perf_event_paranoid check failed"
                }
            );
        }

        rec.push(
            "message",
            Value::string(
                format!(
                    "Run the commands above to fix: {}",
                    issues.join(", ")
                ),
                span,
            ),
        );

        // Add note about persistence
        if !paranoid_ok {
            rec.push(
                "note",
                Value::string(
                    "To make perf_event_paranoid persistent across reboots, add 'kernel.perf_event_paranoid=2' to /etc/sysctl.conf",
                    span,
                ),
            );
        }
    }

    Ok(PipelineData::Value(Value::record(rec, span), None))
}

#[cfg(target_os = "linux")]
fn get_file_capabilities(path: &str) -> String {
    use std::process::Command;

    Command::new("getcap")
        .arg(path)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(target_os = "linux")]
fn get_perf_event_paranoid() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(4) // Default to restrictive if we can't read
}
